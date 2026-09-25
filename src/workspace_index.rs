//! Per-workspace in-memory index, milestone 1 (epic 6b1f3c2).
//!
//! M1 holds, per open workspace handle, beside the rollup cache and the
//! realtime hub: every `records` column except `body`, all `facet_values`,
//! all `links`, and a bounded recent window of `content_events`.
//!
//! Build ([`build_on`]) runs inside one read transaction on the physically
//! read-only pool, stamping the content sequence from the same snapshot, so
//! the held rows equal a fresh read at `built_at_seq` when it returns.
//! Catch-up ([`refresh_from`]) folds committed content events above the
//! cursor off the same commit wake that drives the realtime hub, re-reading
//! only the rows those events name. The read-only pool is used on every
//! path: there is no write-pool acquisition, no `BEGIN IMMEDIATE`, and no
//! expiry — freshness is bounded by invalidation latency, never by a TTL.
//!
//! # The fold boundary — what this log does *not* carry
//!
//! Catch-up is driven by `content_events` alone, and two projections are
//! written outside that log. A fresh read sees them; this index does not until
//! some later content event happens to name a touched record, and never on a
//! quiet workspace:
//!
//! - **Relationship-tier compatibility links.** `rel:<origin>:<id>` rows in
//!   `links` are reconstructed from `relationship_events`
//!   (`relationship::projector`), not from a content event. A relationship
//!   link added between A and B after the index is built therefore does not
//!   fold until a content commit names A or B.
//! - **`records.policy_anchor_id` subtree rewrites.** `refresh_policy_anchor_subtree`
//!   (`authorization.rs`) rewrites the anchor across a whole descendant set; the
//!   triggering content event names only the changed record, so descendants
//!   D1..Dn keep a stale held `policy_anchor_id` until a content commit names
//!   each of them. Treat that field as authorization-relevant if M3 serves it.
//!
//! This is a deliberate M1 boundary, not an oversight: closing it means
//! watching the relationship and authorization fence sequences as well as the
//! content cursor, which is M2/M3 work. A reader that needs
//! equivalence-after-everything must not treat this index as complete across
//! those two tiers.
//!
//! # Memory cap and eviction rule (stated, not assumed)
//!
//! - The `content_events` window is bounded to [`MAX_CONTENT_WINDOW_EVENTS`]
//!   newest entries (payload-free refs); older entries evict oldest-first.
//! - The `records` / `facet_values` / `links` maps are **not** evicted: a
//!   partial map would silently break the equivalence contract this epic
//!   rests on. Instead [`MAX_INDEX_BYTES`] refuses — a workspace whose built
//!   index exceeds the cap simply is not held, and callers stay on the
//!   governed path. See that constant for the measured basis.
//! - The whole index still drops with the handle under the existing 64-handle
//!   LRU, is rebuilt on reopen, and is lost on restart.

use std::collections::{HashMap, HashSet, VecDeque};

use sqlx::Row;

/// Newest content events retained per handle. Payload-free: the window carries
/// ordering and identity for catch-up, never bodies or payloads.
pub const MAX_CONTENT_WINDOW_EVENTS: usize = 512;

/// Refusal threshold for one whole built index, in bytes.
///
/// **Measured, not guessed.** Native HQ's real workspace database
/// (`hq-fixed.db`, 5 Sep 2026) holds 2,829 `records`, 7,130 `facet_values` and
/// 4,621 `links`, carrying 1.39 MB / 1.08 MB / 1.35 MB of held string data
/// respectively — about 492 bytes/record, 152 bytes/facet and 291 bytes/link
/// of raw column text. Through [`WorkspaceIndex::estimated_bytes`] — row
/// struct size plus string heap plus a 50% allowance for the hash tables and
/// keys — that workspace's index costs about **10 MiB**, roughly 3.7 KiB per
/// record once its facets and links are counted.
///
/// 32 MiB is about 3.2x that measured workspace, so an ordinary workspace is
/// never refused, and it bounds the process at 64 handles x 32 MiB = 2 GiB of
/// index even if every resident handle sat at the cap. Above the cap the index
/// **refuses** (leaves itself unheld) rather than evicting a subset — see the
/// module doc; a partially held index would silently break the equivalence
/// contract this epic rests on.
pub const MAX_INDEX_BYTES: usize = 32 * 1024 * 1024;

/// One `records` row minus `body`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordHead {
    pub id: String,
    pub record_type: String,
    pub kind: Option<String>,
    pub name: String,
    pub home_id: Option<String>,
    pub lifecycle: Option<String>,
    pub owner_id: Option<String>,
    pub claimed_by_account: Option<String>,
    pub claimed_run_key: Option<String>,
    pub claimed_at: Option<String>,
    pub policy_anchor_id: Option<String>,
    pub persistence: String,
    pub maturity: Option<String>,
    pub summary: Option<String>,
    pub last_activity_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

/// One `facet_values` row, including the generated numeric projection.
/// `value_num` is `REAL` in SQLite and `Option<f64>` here: `None` exactly when
/// the stored text is not a JSON integer or real. `Eq` is deliberately absent
/// (`f64` has none); map equality for equivalence checks needs `PartialEq` only.
#[derive(Debug, Clone, PartialEq)]
pub struct FacetRow {
    pub id: String,
    pub record_id: String,
    pub key: String,
    pub value: Option<String>,
    pub value_num: Option<f64>,
    pub vocab_ref: Option<String>,
    pub created_at: String,
}

/// One `links` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRow {
    pub id: String,
    pub source_id: String,
    pub target_id: String,
    pub relationship: String,
    pub note: Option<String>,
    pub created_at: String,
}

/// Payload-free content-log ref for the bounded recent window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentEventRef {
    pub seq: i64,
    pub id: String,
    pub record_id: String,
    pub event_type: String,
    pub created_at: String,
}

fn str_heap(value: &str) -> usize {
    value.len()
}

fn opt_str_heap(value: &Option<String>) -> usize {
    value.as_deref().map_or(0, str::len)
}

impl RecordHead {
    fn heap_bytes(&self) -> usize {
        str_heap(&self.id)
            + str_heap(&self.record_type)
            + opt_str_heap(&self.kind)
            + str_heap(&self.name)
            + opt_str_heap(&self.home_id)
            + opt_str_heap(&self.lifecycle)
            + opt_str_heap(&self.owner_id)
            + opt_str_heap(&self.claimed_by_account)
            + opt_str_heap(&self.claimed_run_key)
            + opt_str_heap(&self.claimed_at)
            + opt_str_heap(&self.policy_anchor_id)
            + str_heap(&self.persistence)
            + opt_str_heap(&self.maturity)
            + opt_str_heap(&self.summary)
            + opt_str_heap(&self.last_activity_at)
            + str_heap(&self.created_at)
            + str_heap(&self.updated_at)
            + opt_str_heap(&self.deleted_at)
    }
}

impl FacetRow {
    fn heap_bytes(&self) -> usize {
        str_heap(&self.id)
            + str_heap(&self.record_id)
            + str_heap(&self.key)
            + opt_str_heap(&self.value)
            + self.value_num.map_or(0, |_| 8)
            + opt_str_heap(&self.vocab_ref)
            + str_heap(&self.created_at)
    }
}

impl LinkRow {
    fn heap_bytes(&self) -> usize {
        str_heap(&self.id)
            + str_heap(&self.source_id)
            + str_heap(&self.target_id)
            + str_heap(&self.relationship)
            + opt_str_heap(&self.note)
            + str_heap(&self.created_at)
    }
}

impl ContentEventRef {
    fn heap_bytes(&self) -> usize {
        str_heap(&self.id)
            + str_heap(&self.record_id)
            + str_heap(&self.event_type)
            + str_heap(&self.created_at)
    }
}

/// The per-handle index. Keyed by row id; links additionally indexed by
/// endpoint for target-side coherence on catch-up.
#[derive(Debug, Default, Clone)]
pub struct WorkspaceIndex {
    /// Sequence stamped from the build's single read snapshot (brief §How it
    /// is built). Because the stamp and the row reads share one transaction,
    /// the held rows equal a fresh read at `built_at_seq` when the build
    /// returns; anything committed later is at `seq > built_at_seq` and is
    /// folded by catch-up.
    pub built_at_seq: i64,
    /// Highest content sequence folded in so far (cursor for catch-up).
    pub cursor_seq: i64,
    /// Authorization and relationship fences from the build snapshot. Content
    /// folding does not repair subtree-anchor or `rel:%` projection changes.
    pub authorization_epoch: i64,
    pub relationship_seq: i64,
    pub records: HashMap<String, RecordHead>,
    pub facets: HashMap<String, FacetRow>,
    pub links: HashMap<String, LinkRow>,
    content_window: VecDeque<ContentEventRef>,
}

/// M4 point-read result for one record's facet surface: the held head plus
/// only that record's facet rows (key/id ordered by the extractor). Fence
/// triple retained so reviewers can see what the extractor gated on.
#[derive(Debug, Clone)]
pub struct IndexedFacetsRecord {
    pub head: RecordHead,
    pub facets: Vec<FacetRow>,
    pub content_seq: i64,
    pub authorization_epoch: i64,
    pub relationship_seq: i64,
}

/// M4 point-read result for one record's link surface: only the links
/// touching the record on either endpoint. Fence triple retained for the
/// caller to validate against its governed visible set. An empty `links`
/// with matching fences is a servable answer (a linkless record); anchor
/// existence and visibility stay governed at the call site.
#[derive(Debug, Clone)]
pub struct IndexedLinkCandidates {
    pub links: Vec<LinkRow>,
    pub content_seq: i64,
    pub authorization_epoch: i64,
    pub relationship_seq: i64,
}

/// Internal M2 result. M3 owns the public projection and transport contract.
/// Rows here retain M1's physical shape and must not be serialized directly.
#[derive(Debug, Clone)]
#[allow(dead_code)] // M3 will consume the fields when its transport is added.
pub(crate) struct FilteredWorkspaceIndex {
    pub content_seq: i64,
    pub authorization_epoch: i64,
    pub relationship_seq: i64,
    pub unit_seq_max: i64,
    pub records: HashMap<String, RecordHead>,
    pub facets: HashMap<String, FacetRow>,
    pub links: HashMap<String, LinkRow>,
    pub content_events: Vec<ContentEventRef>,
}

impl FilteredWorkspaceIndex {
    /// Apply the engine's governed answer, without interpreting policy here.
    pub(crate) fn intersect(
        index: &WorkspaceIndex,
        visible: &HashSet<String>,
        authorization_epoch: i64,
        relationship_seq: i64,
        unit_seq_max: i64,
    ) -> Self {
        let records = index
            .records
            .iter()
            .filter_map(|(id, head)| {
                if !visible.contains(id) {
                    return None;
                }
                let mut head = head.clone();
                if head
                    .home_id
                    .as_ref()
                    .is_some_and(|parent| !visible.contains(parent))
                {
                    head.home_id = None;
                }
                Some((id.clone(), head))
            })
            .collect();
        let facets = index
            .facets
            .iter()
            .filter(|(_, facet)| visible.contains(&facet.record_id))
            .map(|(id, facet)| (id.clone(), facet.clone()))
            .collect();
        let links = index
            .links
            .iter()
            .filter(|(_, link)| {
                visible.contains(&link.source_id) && visible.contains(&link.target_id)
            })
            .map(|(id, link)| (id.clone(), link.clone()))
            .collect();
        let content_events = index
            .content_window
            .iter()
            .filter(|event| visible.contains(&event.record_id))
            .filter(|event| {
                !matches!(
                    event.event_type.as_str(),
                    "reconciliation.recorded.v1"
                        | "unit.superseded.v1"
                        | "receipt.dependency_audited.v1"
                )
            })
            .map(|event| {
                let mut event = event.clone();
                if event.event_type == "receipt.committed.v1" {
                    event.event_type = "record.updated".into();
                }
                event
            })
            .collect();
        Self {
            content_seq: index.cursor_seq,
            authorization_epoch,
            relationship_seq,
            unit_seq_max,
            records,
            facets,
            links,
            content_events,
        }
    }
}

impl WorkspaceIndex {
    pub fn new(built_at_seq: i64) -> Self {
        Self {
            built_at_seq,
            cursor_seq: built_at_seq,
            authorization_epoch: 0,
            relationship_seq: 0,
            records: HashMap::new(),
            facets: HashMap::new(),
            links: HashMap::new(),
            content_window: VecDeque::new(),
        }
    }

    /// Push one content ref onto the bounded window, oldest-first eviction.
    /// Idempotent by event id: a catch-up overlapping the build window
    /// re-pushes refs the build already held rather than duplicating them.
    pub fn push_content_event(&mut self, event: ContentEventRef) {
        if event.seq > self.cursor_seq {
            self.cursor_seq = event.seq;
        }
        if let Some(pos) = self
            .content_window
            .iter()
            .position(|existing| existing.id == event.id)
        {
            self.content_window.remove(pos);
        }
        self.content_window.push_back(event);
        while self.content_window.len() > MAX_CONTENT_WINDOW_EVENTS {
            self.content_window.pop_front();
        }
    }

    pub fn content_window(&self) -> &VecDeque<ContentEventRef> {
        &self.content_window
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn facet_count(&self) -> usize {
        self.facets.len()
    }

    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Links touching one record on either endpoint.
    pub fn links_touching<'a>(
        &'a self,
        record_id: &'a str,
    ) -> impl Iterator<Item = &'a LinkRow> + 'a {
        self.links
            .values()
            .filter(move |link| link.source_id == record_id || link.target_id == record_id)
    }

    /// Rough resident size of the held rows, in bytes.
    ///
    /// Sums each row's inline struct size (which already carries every
    /// `String`/`Option<String>` header) and the heap bytes of its strings,
    /// then adds 50% for the hash tables, their tuple keys and slack. This is
    /// approximate on purpose: it gates the [`MAX_INDEX_BYTES`] refusal, not a
    /// byte-accurate accounting. Its calibration against a real workspace is
    /// recorded on that constant.
    pub fn estimated_bytes(&self) -> usize {
        let records: usize = self
            .records
            .values()
            .map(|row| std::mem::size_of::<RecordHead>() + row.heap_bytes())
            .sum();
        let facets: usize = self
            .facets
            .values()
            .map(|row| std::mem::size_of::<FacetRow>() + row.heap_bytes())
            .sum();
        let links: usize = self
            .links
            .values()
            .map(|row| std::mem::size_of::<LinkRow>() + row.heap_bytes())
            .sum();
        let window: usize = self
            .content_window
            .iter()
            .map(|row| std::mem::size_of::<ContentEventRef>() + row.heap_bytes())
            .sum();
        let payload = records + facets + links + window;
        payload + payload / 2
    }

    /// Whether this index is small enough to hold under `cap`. The caller
    /// treats `false` as a refusal and falls back to the governed path; it
    /// must not evict a subset instead.
    pub fn within_cap(&self, cap: usize) -> bool {
        self.estimated_bytes() <= cap
    }
}

/// `records` columns held by the index: every column except `body`.
const RECORD_HEAD_COLUMNS: &str = "id, type, kind, name, home_id, lifecycle, \
    owner_id, claimed_by_account, claimed_run_key, claimed_at, policy_anchor_id, \
    persistence, maturity, summary, last_activity_at, created_at, updated_at, deleted_at";

fn record_head_from_row(row: &sqlx::sqlite::SqliteRow) -> crate::Result<RecordHead> {
    Ok(RecordHead {
        id: row.try_get("id")?,
        record_type: row.try_get("type")?,
        kind: row.try_get("kind")?,
        name: row.try_get("name")?,
        home_id: row.try_get("home_id")?,
        lifecycle: row.try_get("lifecycle")?,
        owner_id: row.try_get("owner_id")?,
        claimed_by_account: row.try_get("claimed_by_account")?,
        claimed_run_key: row.try_get("claimed_run_key")?,
        claimed_at: row.try_get("claimed_at")?,
        policy_anchor_id: row.try_get("policy_anchor_id")?,
        persistence: row.try_get("persistence")?,
        maturity: row.try_get("maturity")?,
        summary: row.try_get("summary")?,
        last_activity_at: row.try_get("last_activity_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        deleted_at: row.try_get("deleted_at")?,
    })
}

fn facet_row_from_row(row: &sqlx::sqlite::SqliteRow) -> crate::Result<FacetRow> {
    Ok(FacetRow {
        id: row.try_get("id")?,
        record_id: row.try_get("record_id")?,
        key: row.try_get("key")?,
        value: row.try_get("value")?,
        value_num: row.try_get("value_num")?,
        vocab_ref: row.try_get("vocab_ref")?,
        created_at: row.try_get("created_at")?,
    })
}

fn link_row_from_row(row: &sqlx::sqlite::SqliteRow) -> crate::Result<LinkRow> {
    Ok(LinkRow {
        id: row.try_get("id")?,
        source_id: row.try_get("source_id")?,
        target_id: row.try_get("target_id")?,
        relationship: row.try_get("relationship")?,
        note: row.try_get("note")?,
        created_at: row.try_get("created_at")?,
    })
}

fn content_ref_from_row(row: &sqlx::sqlite::SqliteRow) -> crate::Result<ContentEventRef> {
    Ok(ContentEventRef {
        seq: row.try_get("seq")?,
        id: row.try_get("id")?,
        record_id: row.try_get("record_id")?,
        event_type: row.try_get("type")?,
        created_at: row.try_get("created_at")?,
    })
}

/// Build the index with one local read on the physically read-only pool.
///
/// The caller passes `db.pool()` (never the write pool). Every read below runs
/// inside **one deferred read transaction**, so the content stamp and the three
/// projection reads come from a single SQLite snapshot. That is what makes the
/// build boundary honest: without it the four `SELECT`s are separate autocommit
/// reads, and a write landing between them yields a torn view (a new facet
/// against a stale record head) that the pre-read stamp alone cannot repair,
/// because the commit that produced it fires its wake while this handle still
/// has no index and the fold no-ops.
///
/// With one snapshot the invariant is structural, not procedural: the held rows
/// equal a fresh read of the three tables at `built_at_seq` the moment the
/// build returns. Events committed after the snapshot land at `seq >
/// built_at_seq` and are folded by catch-up; the cursor stays at the stamp, so
/// nothing above it is skipped. The transaction is deferred and the connection
/// is physically read-only — plain `SELECT`s, no `BEGIN IMMEDIATE`, no
/// write-pool slot — so this cannot join the writer serialization the 16 Sep
/// campaign mapped.
pub async fn build_on(pool: &sqlx::SqlitePool) -> crate::Result<WorkspaceIndex> {
    let mut tx = pool.begin().await.map_err(crate::Error::from)?;
    // Read the stamp first: the first read of a deferred transaction fixes the
    // snapshot, so the stamp can never name an event the table reads below lack.
    let stamp: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
        .fetch_one(&mut *tx)
        .await
        .map_err(crate::Error::from)?;
    let mut index = WorkspaceIndex::new(stamp);
    index.authorization_epoch =
        sqlx::query_scalar("SELECT epoch FROM authorization_revision WHERE id = 1")
            .fetch_one(&mut *tx)
            .await
            .map_err(crate::Error::from)?;
    index.relationship_seq =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM relationship_events")
            .fetch_one(&mut *tx)
            .await
            .map_err(crate::Error::from)?;

    let record_rows = sqlx::query(&format!(
        "SELECT {RECORD_HEAD_COLUMNS} FROM records ORDER BY id"
    ))
    .fetch_all(&mut *tx)
    .await
    .map_err(crate::Error::from)?;
    for row in &record_rows {
        let head = record_head_from_row(row)?;
        index.records.insert(head.id.clone(), head);
    }

    let facet_rows = sqlx::query(
        "SELECT id, record_id, key, value, value_num, vocab_ref, created_at FROM facet_values",
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(crate::Error::from)?;
    for row in &facet_rows {
        let facet = facet_row_from_row(row)?;
        index.facets.insert(facet.id.clone(), facet);
    }

    let link_rows =
        sqlx::query("SELECT id, source_id, target_id, relationship, note, created_at FROM links")
            .fetch_all(&mut *tx)
            .await
            .map_err(crate::Error::from)?;
    for row in &link_rows {
        let link = link_row_from_row(row)?;
        index.links.insert(link.id.clone(), link);
    }

    // Bounded newest-first window, stored oldest-first, from the same snapshot.
    // These refs are held for ordering and identity only; they are not yet
    // folded into the row maps. The cursor stays at the stamp, so the catch-up
    // that follows folds every event above it (a no-op when the window is the
    // whole tail), and folding is idempotent by row.
    let window_rows = sqlx::query(
        "SELECT seq, id, record_id, type, created_at FROM content_events \
         ORDER BY seq DESC LIMIT ?",
    )
    .bind(MAX_CONTENT_WINDOW_EVENTS as i64)
    .fetch_all(&mut *tx)
    .await
    .map_err(crate::Error::from)?;
    let mut window: Vec<ContentEventRef> = window_rows
        .iter()
        .map(content_ref_from_row)
        .collect::<crate::Result<_>>()?;
    window.sort_by_key(|event| event.seq);
    for event in window {
        index.content_window.push_back(event);
    }
    while index.content_window.len() > MAX_CONTENT_WINDOW_EVENTS {
        index.content_window.pop_front();
    }
    tx.rollback().await.map_err(crate::Error::from)?;
    Ok(index)
}

/// Catch-up page size: the same bound the realtime hub tails with.
const REFRESH_PAGE: i64 = 256;

impl WorkspaceIndex {
    /// Map-level equality for equivalence checks (cursors compared separately).
    pub fn same_rows(&self, other: &Self) -> bool {
        self.records == other.records && self.facets == other.facets && self.links == other.links
    }
}

/// Fold content events newer than the cursor into the index, read-pool only.
///
/// For every event with `seq` in `(cursor, fence]`, re-reads the named
/// record's head row, its facet rows, and its touching links, then advances
/// the cursor past it. Idempotent: re-folding an already-folded event
/// re-reads the same rows. Returns the number of events folded. Plain
/// `SELECT`s only: no `BEGIN IMMEDIATE`, no write-pool slot.
pub async fn refresh_from(
    pool: &sqlx::SqlitePool,
    index: &mut WorkspaceIndex,
) -> crate::Result<usize> {
    let fence: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
        .fetch_one(pool)
        .await
        .map_err(crate::Error::from)?;
    let mut folded = 0;
    while index.cursor_seq < fence {
        let rows = sqlx::query(
            "SELECT seq, id, record_id, type, created_at FROM content_events \
             WHERE seq > ? AND seq <= ? ORDER BY seq LIMIT ?",
        )
        .bind(index.cursor_seq)
        .bind(fence)
        .bind(REFRESH_PAGE)
        .fetch_all(pool)
        .await
        .map_err(crate::Error::from)?;
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            let event = content_ref_from_row(row)?;
            refresh_record(pool, index, &event.record_id).await?;
            index.push_content_event(event);
            folded += 1;
        }
    }
    Ok(folded)
}

/// Re-read one record's held rows. A missing head row mirrors SQLite's
/// `ON DELETE CASCADE` in memory: the head, its facets, and its touching
/// links all drop.
async fn refresh_record(
    pool: &sqlx::SqlitePool,
    index: &mut WorkspaceIndex,
    record_id: &str,
) -> crate::Result<()> {
    let head = sqlx::query(&format!(
        "SELECT {RECORD_HEAD_COLUMNS} FROM records WHERE id = ?"
    ))
    .bind(record_id)
    .fetch_optional(pool)
    .await
    .map_err(crate::Error::from)?;
    let Some(head) = head else {
        index.records.remove(record_id);
        index.facets.retain(|_, facet| facet.record_id != record_id);
        index
            .links
            .retain(|_, link| link.source_id != record_id && link.target_id != record_id);
        return Ok(());
    };
    let head = record_head_from_row(&head)?;
    index.records.insert(head.id.clone(), head);

    let facet_rows = sqlx::query(
        "SELECT id, record_id, key, value, value_num, vocab_ref, created_at \
         FROM facet_values WHERE record_id = ?",
    )
    .bind(record_id)
    .fetch_all(pool)
    .await
    .map_err(crate::Error::from)?;
    let mut seen_facets = std::collections::HashSet::new();
    for row in &facet_rows {
        let facet = facet_row_from_row(row)?;
        seen_facets.insert(facet.id.clone());
        index.facets.insert(facet.id.clone(), facet);
    }
    index
        .facets
        .retain(|_, facet| facet.record_id != record_id || seen_facets.contains(&facet.id));

    // Either endpoint: the event names the source, but the link row is one
    // shared row, so refreshing covers the target side too.
    let link_rows = sqlx::query(
        "SELECT id, source_id, target_id, relationship, note, created_at \
         FROM links WHERE source_id = ? OR target_id = ?",
    )
    .bind(record_id)
    .bind(record_id)
    .fetch_all(pool)
    .await
    .map_err(crate::Error::from)?;
    let mut seen_links = std::collections::HashSet::new();
    for row in &link_rows {
        let link = link_row_from_row(row)?;
        seen_links.insert(link.id.clone());
        index.links.insert(link.id.clone(), link);
    }
    // Prune only links that touched this record and vanished; links between
    // two other records are untouched by this event.
    let touching: Vec<String> = index
        .links
        .iter()
        .filter(|(_, link)| link.source_id == record_id || link.target_id == record_id)
        .map(|(id, _)| id.clone())
        .collect();
    for id in touching {
        if !seen_links.contains(&id) {
            index.links.remove(&id);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(id: &str, source: &str, target: &str) -> LinkRow {
        LinkRow {
            id: id.into(),
            source_id: source.into(),
            target_id: target.into(),
            relationship: "part_of".into(),
            note: None,
            created_at: "2026-09-21T00:00:00.000Z".into(),
        }
    }

    #[test]
    fn content_window_evicts_oldest_first() {
        let mut index = WorkspaceIndex::new(0);
        for seq in 1..=(MAX_CONTENT_WINDOW_EVENTS as i64 + 2) {
            index.push_content_event(ContentEventRef {
                seq,
                id: format!("e{seq}"),
                record_id: "r".into(),
                event_type: "record.updated".into(),
                created_at: "2026-09-21T00:00:00.000Z".into(),
            });
        }
        assert_eq!(index.content_window().len(), MAX_CONTENT_WINDOW_EVENTS);
        assert_eq!(index.content_window().front().unwrap().seq, 3);
        assert_eq!(index.cursor_seq, MAX_CONTENT_WINDOW_EVENTS as i64 + 2);
    }

    #[test]
    fn links_touching_covers_both_endpoints() {
        let mut index = WorkspaceIndex::new(0);
        index.links.insert("l1".into(), link("l1", "a", "b"));
        index.links.insert("l2".into(), link("l2", "c", "a"));
        index.links.insert("l3".into(), link("l3", "b", "c"));
        let touching: Vec<_> = index.links_touching("a").map(|l| l.id.as_str()).collect();
        assert_eq!(touching.len(), 2);
        assert!(touching.contains(&"l1"));
        assert!(touching.contains(&"l2"));
    }

    #[tokio::test]
    async fn build_holds_everything_but_body_on_the_read_pool() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let id = crate::store::create_record(
            &db,
            serde_json::json!({
                "id": "5f1a0000-0000-4000-8000-000000000001",
                "type": "Document",
                "kind": "note",
                "name": "indexed",
                "body": "must not be held",
            }),
        )
        .await
        .unwrap();
        crate::store::set_facet(
            &db,
            &id,
            crate::events::FacetSetPayload {
                key: "status".into(),
                value: Some("open".into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        let other = crate::store::create_record(
            &db,
            serde_json::json!({
                "id": "5f1a0000-0000-4000-8000-000000000002",
                "type": "Document",
                "kind": "note",
                "name": "other",
            }),
        )
        .await
        .unwrap();
        crate::store::add_link(
            &db,
            crate::events::LinkAddedPayload {
                id: None,
                source_id: id.clone(),
                target_id: other.clone(),
                // Content-owned (see relationship::legacy::classify): the
                // content projector writes the links row for this.
                relationship: "part_of".into(),
                note: None,
            },
        )
        .await
        .unwrap();

        // Read-pool only: the build runs inside the read counter's scope and
        // must acquire no write-pool connection.
        let ((index, reads), writes) = crate::db::with_write_pool_acquisition_counter(async {
            crate::db::with_read_pool_acquisition_counter(async {
                super::build_on(db.pool()).await.unwrap()
            })
            .await
        })
        .await;
        assert!(reads > 0);
        assert_eq!(writes, 0);
        assert_eq!(
            index.built_at_seq,
            sqlx::query_scalar::<_, i64>("SELECT COALESCE(MAX(seq), 0) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap()
        );
        let head = index.records.get(&id).unwrap();
        assert_eq!(head.name, "indexed");
        assert_eq!(head.kind.as_deref(), Some("note"));
        assert_eq!(index.facet_count(), 1);
        assert_eq!(index.link_count(), 1);
        assert!(index.content_window().len() >= 4);
        // Bodies are never held: the type has no field for one, and a fresh
        // read of the held columns matches the live table.
        let live_name: String = sqlx::query_scalar("SELECT name FROM records WHERE id = ?")
            .bind(&id)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(live_name, head.name);
        db.close().await;
    }

    #[tokio::test]
    async fn direct_catch_up_matches_a_fresh_build_with_no_write_pool_use() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let id = crate::store::create_record(
            &db,
            serde_json::json!({
                "id": "6c2b0000-0000-4000-8000-000000000001",
                "type": "Document", "kind": "note", "name": "first",
            }),
        )
        .await
        .unwrap();
        let mut index = super::build_on(db.pool()).await.unwrap();

        // Mixed writes after the build: update, facet set + unset, link add +
        // remove, a fresh record, and a record delete (row kept, tombstoned).
        crate::store::update_record(&db, &id, serde_json::json!({"name": "renamed"}))
            .await
            .unwrap();
        crate::store::set_facet(
            &db,
            &id,
            crate::events::FacetSetPayload {
                key: "tag".into(),
                value: Some("kept".into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        crate::store::set_facet(
            &db,
            &id,
            crate::events::FacetSetPayload {
                key: "temp".into(),
                value: Some("gone".into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        crate::store::unset_facet(&db, &id, "temp").await.unwrap();
        let other = crate::store::create_record(
            &db,
            serde_json::json!({
                "id": "6c2b0000-0000-4000-8000-000000000002",
                "type": "Document", "kind": "note", "name": "second",
            }),
        )
        .await
        .unwrap();
        crate::store::add_link(
            &db,
            crate::events::LinkAddedPayload {
                id: None,
                source_id: id.clone(),
                target_id: other.clone(),
                relationship: "part_of".into(),
                note: None,
            },
        )
        .await
        .unwrap();
        crate::store::remove_link(
            &db,
            crate::events::LinkRemovedPayload {
                source_id: id.clone(),
                target_id: other.clone(),
                relationship: "part_of".into(),
            },
        )
        .await
        .unwrap();
        crate::store::delete_record(&db, &other).await.unwrap();

        let (folded, writes) = crate::db::with_write_pool_acquisition_counter(async {
            super::refresh_from(db.pool(), &mut index).await.unwrap()
        })
        .await;
        assert!(folded > 0);
        // Scoped to the direct `refresh_from` call, which runs inside the
        // counter's task-local scope. This proves the direct catch-up path
        // acquires no write-pool connection. It does NOT cover the spawned
        // production fold (`Db::spawn_workspace_index_fold`): the counter's own
        // documentation records that write-pool use in a spawned task is not
        // attributed, so the wake path is verified by inspection on the same
        // read-only calls, not by this assertion.
        assert_eq!(writes, 0);

        let fresh = super::build_on(db.pool()).await.unwrap();
        assert!(index.same_rows(&fresh));
        assert_eq!(index.cursor_seq, fresh.cursor_seq);
        assert_eq!(index.records.get(&id).unwrap().name, "renamed");
        assert!(index.records.get(&other).unwrap().deleted_at.is_some());
        assert!(index.links_touching(&id).next().is_none());
        db.close().await;
    }

    #[tokio::test]
    async fn burst_of_concurrent_writes_folds_without_miss_or_duplicate() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        const WRITERS: usize = 8;
        const PER_WRITER: usize = 5;
        const FOLDERS: usize = 4;

        let db = crate::db::create_database(":memory:").await.unwrap();
        let index = Arc::new(tokio::sync::Mutex::new(
            super::build_on(db.pool()).await.unwrap(),
        ));
        let before = index.lock().await.cursor_seq;

        let remaining = Arc::new(AtomicUsize::new(WRITERS));
        let mut writers = Vec::new();
        for task in 0..WRITERS {
            let db = db.clone();
            let remaining = remaining.clone();
            writers.push(tokio::spawn(async move {
                for item in 0..PER_WRITER {
                    crate::store::create_record(
                        &db,
                        serde_json::json!({
                            "id": uuid::Uuid::new_v4().to_string(),
                            "type": "Document", "kind": "note",
                            "name": format!("burst-{task}-{item}"),
                        }),
                    )
                    .await
                    .unwrap();
                }
                remaining.fetch_sub(1, Ordering::SeqCst);
            }));
        }

        // Fold *while* the writers run: this is the interleaving the acceptance
        // criterion is about — a fold racing a commit — not one catch-up after
        // the burst. The Mutex serializes folders, and the cursor is monotonic,
        // so each committed event is folded exactly once.
        let folded_total = Arc::new(AtomicUsize::new(0));
        let mut folders = Vec::new();
        for _ in 0..FOLDERS {
            let db = db.clone();
            let index = index.clone();
            let remaining = remaining.clone();
            let folded_total = folded_total.clone();
            folders.push(tokio::spawn(async move {
                while remaining.load(Ordering::SeqCst) > 0 {
                    let folded = {
                        let mut guard = index.lock().await;
                        super::refresh_from(db.pool(), &mut guard).await.unwrap()
                    };
                    folded_total.fetch_add(folded, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                }
                // Final sweep: a commit may have landed after the last check.
                let folded = {
                    let mut guard = index.lock().await;
                    super::refresh_from(db.pool(), &mut guard).await.unwrap()
                };
                folded_total.fetch_add(folded, Ordering::SeqCst);
            }));
        }

        for writer in writers {
            writer.await.unwrap();
        }
        for folder in folders {
            folder.await.unwrap();
        }

        let guard = index.lock().await;
        let fresh = super::build_on(db.pool()).await.unwrap();
        assert!(guard.same_rows(&fresh));
        assert_eq!(guard.cursor_seq, fresh.cursor_seq);
        assert!(guard.cursor_seq > before);
        // No missed and no duplicated row: the concurrent folders advanced the
        // cursor through exactly the 40 committed events, each folded once.
        assert_eq!(folded_total.load(Ordering::SeqCst), WRITERS * PER_WRITER);
        assert_eq!(
            folded_total.load(Ordering::SeqCst),
            (guard.cursor_seq - before) as usize
        );
        // Head count matches the live table exactly.
        let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(guard.record_count() as i64, live);
        drop(guard);
        db.close().await;
    }

    #[tokio::test]
    async fn handle_index_starts_cold_and_a_second_handle_starts_cold() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m1-lifecycle.db");
        let db = crate::db::create_database(path.to_str().unwrap())
            .await
            .unwrap();
        assert!(!db.workspace_index_built_for_tests().await);
        db.ensure_workspace_index().await.unwrap();
        assert!(db.workspace_index_built_for_tests().await);

        // Reopening the same file starts cold: the index is handle state,
        // evicted with the handle under the router LRU, never shared.
        let reopened = crate::db::open_existing_database_at(&path).await.unwrap();
        assert!(!reopened.workspace_index_built_for_tests().await);
        db.close().await;
        reopened.close().await;
    }

    #[tokio::test]
    async fn commit_wake_folds_without_an_explicit_refresh() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        db.ensure_workspace_index().await.unwrap();
        let before = db
            .workspace_index_snapshot_for_tests()
            .await
            .unwrap()
            .cursor_seq;

        let id = crate::store::create_record(
            &db,
            serde_json::json!({
                "id": "8e4d0000-0000-4000-8000-000000000001",
                "type": "Document", "kind": "note", "name": "wake-folded",
            }),
        )
        .await
        .unwrap();

        // The commit wake folds in the background: poll, don't sleep once.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let cursor = db
                .workspace_index_snapshot_for_tests()
                .await
                .unwrap()
                .cursor_seq;
            if cursor > before {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "commit wake did not fold the index"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let snapshot = db.workspace_index_snapshot_for_tests().await.unwrap();
        let fresh = super::build_on(db.pool()).await.unwrap();
        assert!(snapshot.same_rows(&fresh));
        assert_eq!(snapshot.records.get(&id).unwrap().name, "wake-folded");
        db.close().await;
    }

    #[tokio::test]
    async fn a_small_index_is_within_cap_and_an_oversized_one_is_refused() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let id = crate::store::create_record(
            &db,
            serde_json::json!({
                "id": "9f5e0000-0000-4000-8000-000000000001",
                "type": "Document", "kind": "note", "name": "sized",
            }),
        )
        .await
        .unwrap();
        let built = super::build_on(db.pool()).await.unwrap();
        // A realistic workspace is held: the measured basis for the cap is on
        // MAX_INDEX_BYTES, and a small workspace sits well under it.
        assert!(built.within_cap(MAX_INDEX_BYTES));
        assert!(built.estimated_bytes() > 0);
        assert_eq!(built.records.get(&id).unwrap().name, "sized");
        // The refusal predicate is exact: one byte under the measured size
        // declines the index, so `ensure_workspace_index` leaves it unheld and
        // callers stay on the governed path rather than holding a subset.
        assert!(!built.within_cap(built.estimated_bytes() - 1));
        db.close().await;
    }
}
