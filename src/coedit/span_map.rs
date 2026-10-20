//! Per-version span authorship (`span_map` v1 core, task `632ddcc`).
//!
//! A span map answers "who wrote this sentence" for one committed body: it
//! tiles the body's UTF-8 bytes with maximal ranges, each naming one author.
//! Authors live in a deduplicated table inside the map itself — never as
//! indices into the version's `contributors[]`, which keeps meaning "activity
//! since the last cut" unchanged.
//!
//! Ownership is tracked as `(client, UTF-16 clock)` intervals, recorded for
//! every accepted state-changing apply and retained across version drains and
//! peer departures. Yjs clocks tick in UTF-16 code units regardless of the
//! doc's [`OffsetKind::Bytes`](yrs::OffsetKind::Bytes) text encoding (yrs
//! splits and measures items in UTF-16 internally), while the emitted spans
//! are UTF-8 byte ranges of the committed body.
//!
//! Three authorship sources exist, and unknown is never prior version:
//!
//! - [`Owner::PriorVersion`] — the seed interval: text present when the
//!   session opened, recorded once at open from the fresh doc's state vector.
//! - [`Owner::Contributor`] — the full verified contributor row asserted by
//!   the trusted caller at apply time, including `run_key`/`app`/`channel`,
//!   so two routed writers sharing one server client id still split.
//! - [`Owner::Unattributed`] — the explicit unattributed source of legacy
//!   core calls. Production verified calls must resolve contributors; raw
//!   calls keep working without masquerading as prior version.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::Value;

use yrs::{IdSet, StateVector};

use super::registry::{AcknowledgedContributor, AppAttribution};

/// Schema version of the in-memory span map (and its future serialized form).
pub const SPAN_MAP_SCHEMA_VERSION: u8 = 1;
/// Offset kind of every emitted span range: UTF-8 bytes of the committed body.
pub const SPAN_OFFSET_KIND: &str = "bytes";
/// Most spans one map may carry. Bounds the durable event: spans are small
/// integer triples, and 32768 of them stay far under the 1 MiB serialized cap
/// for any realistic body (the body itself is capped at 1 MiB).
pub const MAX_SPAN_MAP_SPANS: usize = 32768;
/// Most bytes one serialized span map may occupy in a version payload.
pub const MAX_SERIALIZED_SPAN_MAP_BYTES: usize = 1024 * 1024;
/// Most distinct authors one map may name: every retained contributor
/// identity plus the prior-version sentinel and the explicit unattributed
/// source. Enforced when assembling the version payload (defense in depth:
/// the ledger budgets already bound this prospectively).
pub const MAX_SPAN_MAP_AUTHORS: usize = MAX_RETAINED_OWNERS + 2;
/// Most ownership intervals retained per live session. Each accepted apply
/// adds at most a handful (usually one per authoring client), adjacent
/// same-owner intervals coalesce on insert, and every version cut prunes to
/// the visible set — so ordinary editing never approaches this; it exists so
/// pathological alternating edits refuse instead of growing without bound.
pub const MAX_OWNERSHIP_INTERVALS: usize = 32768;
/// Most distinct retained contributor identities, mirroring
/// [`MAX_ATTRIBUTED_IDENTITIES`](super::registry::MAX_ATTRIBUTED_IDENTITIES):
/// the retained ledger must not outgrow the pending-attribution budget it
/// generalizes across cuts.
pub const MAX_RETAINED_OWNERS: usize = 1024;
/// Most aggregate UTF-8 identity bytes retained, mirroring
/// [`MAX_ATTRIBUTED_IDENTITY_BYTES`](super::registry::MAX_ATTRIBUTED_IDENTITY_BYTES).
pub const MAX_RETAINED_OWNER_BYTES: usize = 64 * 1024;

/// Who owns a clock interval: the author a span range will name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Owner {
    /// Text present when the session opened (the seed interval).
    PriorVersion,
    /// A verified contributor row, in full: principal, executor kind,
    /// run key, app and channel all distinguish, so identity survives peer
    /// reuse of a client id and routed-write reuse of the server client id.
    Contributor(AcknowledgedContributor),
    /// Explicit unattributed source (legacy core calls). Never prior version.
    Unattributed,
}

impl Owner {
    pub(crate) fn budgeted_bytes(&self) -> usize {
        match self {
            Owner::Contributor(fact) => fact.budgeted_bytes(),
            Owner::PriorVersion | Owner::Unattributed => 0,
        }
    }
}

/// Why ownership recording or map building failed. Variants carry no body
/// text and no identity material beyond the client/clock that needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnershipError {
    /// The successor ledger would exceed its interval, owner-count or
    /// owner-bytes budget. The registry maps this to a `TooLarge` refusal
    /// before the live doc is touched.
    BudgetExhausted,
    /// A clock advance names a client outside the u32 lease/seed/server
    /// space. Unreachable past the authorship gate; mapped to a shape-class
    /// refusal rather than recorded.
    ForeignClient,
}

/// Why a span map could not be built or does not validate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpanBuildError {
    /// Diff chunks do not reconstruct the committed body.
    ReconstructionMismatch,
    /// No ownership interval covers a chunk clock. Missing tracking in an
    /// admitted live/routed doc fails closed here: it must never fall back
    /// to unattributed (which is reserved for intervals explicitly stamped
    /// that way by legacy unattributed core calls) and never to prior.
    UnknownOwner { client: u32, clock: u32 },
    /// One character's UTF-16 units span two owners (invariant breach:
    /// items never split a char across owners).
    SplitChar,
    /// More than [`MAX_SPAN_MAP_SPANS`] spans.
    TooManySpans,
    /// Wrong schema version.
    BadVersion { found: u8 },
    /// Malformed map structure (not an object, missing keys, wrong shapes).
    Malformed,
    /// Spans do not tile `[0, body.len())` exactly: gap, overlap, empty,
    /// out-of-range, or a trailing shortfall.
    BadTiling { index: usize },
    /// A span edge lands inside a character.
    BadCharBoundary { index: usize },
    /// A span names an author outside the map's author table.
    BadAuthorRef { index: usize },
    /// Adjacent spans name the same author: the map is not maximal.
    NotMaximal { index: usize },
    /// An author-table row is never referenced by any span.
    UnusedAuthor { index: usize },
    /// Two author-table rows are identical: the table is not deduplicated.
    DuplicateAuthor { index: usize },
}

/// Clock-interval ownership ledger for one live session.
///
/// Key `(client, start_clock)` maps to `(end_clock_exclusive, owner)`.
/// Entries never overlap: new advances always start where the doc's state
/// vector already ended, and each insert clamps past existing coverage and
/// coalesces with an adjacent same-owner predecessor, so item splits (which
/// subdivide clocks under the same owner) can neither break lookups nor grow
/// the map. Lookups resolve any clock inside an entry to its owner, which is
/// what makes per-item diff chunks attributable without further arithmetic.
#[derive(Debug, Clone, Default)]
pub struct OwnershipLedger {
    intervals: BTreeMap<(u32, u32), (u32, Owner)>,
    contributors: HashSet<AcknowledgedContributor>,
    contributor_bytes: usize,
}

impl OwnershipLedger {
    /// Empty ledger: no ownership is known.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of retained intervals.
    pub fn len(&self) -> usize {
        self.intervals.len()
    }

    /// Whether no interval is retained.
    pub fn is_empty(&self) -> bool {
        self.intervals.is_empty()
    }

    /// Owner of `(client, clock)`, if any interval covers it.
    pub fn owner_at(&self, client: u32, clock: u32) -> Option<&Owner> {
        self.owner_interval_at(client, clock)
            .map(|(_, owner)| owner)
    }

    /// Containing interval for `(client, clock)`: its end clock (exclusive)
    /// plus the owner. A walk advancing through one interval reuses the
    /// cached end instead of a tree lookup per unit.
    pub fn owner_interval_at(&self, client: u32, clock: u32) -> Option<(u32, &Owner)> {
        let ((entry_client, _), (end, owner)) =
            self.intervals.range(..=(client, clock)).next_back()?;
        if *entry_client == client && clock < *end {
            Some((*end, owner))
        } else {
            None
        }
    }

    /// Distinct retained contributor identities (budget accounting).
    pub fn contributor_count(&self) -> usize {
        self.contributors.len()
    }

    /// Aggregate retained contributor identity bytes (budget accounting).
    pub fn contributor_bytes(&self) -> usize {
        self.contributor_bytes
    }

    /// Record a state-vector advance under `owner`: every per-client range
    /// `[before, after)` becomes owned. New ranges are computed first and
    /// the budgets are checked before anything is inserted, so an
    /// over-budget advance refuses without mutating the ledger.
    pub fn record_advance(
        &mut self,
        before: &StateVector,
        after: &StateVector,
        owner: &Owner,
    ) -> Result<(), OwnershipError> {
        let mut ranges = Vec::new();
        for (client, end) in after.iter() {
            let start = before.get(client);
            let end = *end;
            if end > start {
                let client =
                    u32::try_from(client.get()).map_err(|_| OwnershipError::ForeignClient)?;
                ranges.push((client, start, end));
            }
        }
        self.record_ranges(&ranges, owner)
    }

    /// Record explicit `(client, start_clock, end_clock_exclusive)` ranges
    /// under `owner`, with the same check-before-insert budget behavior as
    /// [`OwnershipLedger::record_advance`].
    pub fn record_ranges(
        &mut self,
        ranges: &[(u32, u32, u32)],
        owner: &Owner,
    ) -> Result<(), OwnershipError> {
        // Clamp past existing coverage and count net-new intervals, so the
        // budget decision is exact before the first insert lands.
        let mut clamped = Vec::with_capacity(ranges.len());
        for &(client, start, end) in ranges {
            let mut start = start;
            if let Some(((entry_client, _), (entry_end, _))) =
                self.intervals.range(..=(client, start)).next_back()
            {
                if *entry_client == client && *entry_end > start {
                    start = *entry_end;
                }
            }
            if start >= end {
                continue;
            }
            clamped.push((client, start, end));
        }
        // Nothing new to retain (delete-only updates and replays advance no
        // clocks): succeed regardless of budgets, so deletions never fail
        // for want of an identity entry they do not need.
        if clamped.is_empty() {
            return Ok(());
        }
        let net_new = clamped
            .iter()
            .filter(|&&(client, start, _)| !self.merges_with_predecessor(client, start, owner))
            .count();
        if self.intervals.len() + net_new > MAX_OWNERSHIP_INTERVALS {
            return Err(OwnershipError::BudgetExhausted);
        }
        if let Owner::Contributor(fact) = owner {
            if !self.contributors.contains(fact)
                && (self.contributors.len() >= MAX_RETAINED_OWNERS
                    || self.contributor_bytes.saturating_add(fact.budgeted_bytes())
                        > MAX_RETAINED_OWNER_BYTES)
            {
                return Err(OwnershipError::BudgetExhausted);
            }
        }
        for (client, start, end) in clamped {
            self.insert_interval(client, start, end, owner.clone());
        }
        Ok(())
    }

    /// Whether inserting `[start, _)` for `owner` would coalesce with an
    /// adjacent same-owner predecessor instead of adding an interval.
    fn merges_with_predecessor(&self, client: u32, start: u32, owner: &Owner) -> bool {
        self.intervals
            .range(..=(client, start))
            .next_back()
            .is_some_and(|((entry_client, _), (entry_end, entry_owner))| {
                *entry_client == client && *entry_end == start && entry_owner == owner
            })
    }

    /// Insert one clamped range, extending an adjacent same-owner
    /// predecessor when there is one.
    fn insert_interval(&mut self, client: u32, start: u32, end: u32, owner: Owner) {
        let predecessor = self
            .intervals
            .range(..=(client, start))
            .next_back()
            .map(|(key, value)| (*key, value.clone()));
        if let Some(((entry_client, entry_start), (entry_end, entry_owner))) = predecessor {
            if entry_client == client && entry_end == start && entry_owner == owner {
                self.intervals
                    .insert((entry_client, entry_start), (end, owner.clone()));
                self.note_contributor(&owner);
                return;
            }
        }
        self.intervals.insert((client, start), (end, owner.clone()));
        self.note_contributor(&owner);
    }

    /// Track a newly retained contributor identity for the owner budgets.
    fn note_contributor(&mut self, owner: &Owner) {
        if let Owner::Contributor(fact) = owner {
            if self.contributors.insert(fact.clone()) {
                self.contributor_bytes =
                    self.contributor_bytes.saturating_add(fact.budgeted_bytes());
            }
        }
    }

    /// Prune intervals covered by `deleted` (a doc's delete set): subtract
    /// deleted clock ranges per client, splitting entries into surviving
    /// fragments, and rebuild the contributor budgets from what survives so
    /// the budget recovers. Deleted text needs no attribution; this is what
    /// lets a deletion/replacement at full budget free the space it deletes
    /// before any final budget decision.
    pub fn retain_not_deleted(&mut self, deleted: &IdSet) {
        if deleted.is_empty() {
            return;
        }
        let mut by_client: HashMap<u32, Vec<std::ops::Range<u32>>> = HashMap::new();
        for (client, ranges) in deleted.iter() {
            if let Ok(client) = u32::try_from(client.get()) {
                by_client
                    .entry(client)
                    .or_default()
                    .extend(ranges.iter().cloned());
            }
        }
        if by_client.is_empty() {
            return;
        }
        // Delete ranges arrive sorted and disjoint per client; merge
        // defensively so the sweep below stays linear.
        for ranges in by_client.values_mut() {
            ranges.sort_by_key(|range| (range.start, range.end));
            let mut merged: Vec<std::ops::Range<u32>> = Vec::with_capacity(ranges.len());
            for range in ranges.drain(..) {
                if let Some(last) = merged.last_mut() {
                    if range.start <= last.end {
                        last.end = last.end.max(range.end);
                        continue;
                    }
                }
                merged.push(range);
            }
            *ranges = merged;
        }
        let mut kept: BTreeMap<(u32, u32), (u32, Owner)> = BTreeMap::new();
        // Intervals iterate in `(client, start)` order, so each client's
        // group sweeps its delete ranges once: O(intervals + ranges).
        let mut group_client: Option<u32> = None;
        let mut group_ranges: &[std::ops::Range<u32>] = &[];
        let mut cursor = 0usize;
        for ((client, start), (end, owner)) in &self.intervals {
            if group_client != Some(*client) {
                group_client = Some(*client);
                group_ranges = by_client.get(client).map(Vec::as_slice).unwrap_or(&[]);
                cursor = 0;
            }
            let (mut start, end) = (*start, *end);
            while cursor < group_ranges.len() && group_ranges[cursor].end <= start {
                cursor += 1;
            }
            let mut scan = cursor;
            while scan < group_ranges.len() && group_ranges[scan].start < end {
                let range = &group_ranges[scan];
                if start < range.start {
                    kept.insert((*client, start), (range.start.min(end), owner.clone()));
                }
                start = range.end.max(start);
                if start >= end {
                    break;
                }
                scan += 1;
            }
            if start < end {
                kept.insert((*client, start), (end, owner.clone()));
            }
        }
        self.intervals = kept;
        self.rebuild_contributor_budgets();
    }

    /// Recompute the contributor budgets from the retained intervals.
    fn rebuild_contributor_budgets(&mut self) {
        let owners: Vec<Owner> = self
            .intervals
            .values()
            .map(|(_, owner)| owner.clone())
            .collect();
        self.contributors.clear();
        self.contributor_bytes = 0;
        for owner in &owners {
            self.note_contributor(owner);
        }
    }

    /// Prune to exactly the visible intervals: keep ledger entries
    /// overlapping `visible` `(client, start_clock, end_clock_exclusive)`
    /// triples, drop the rest (deleted text needs no attribution), and
    /// rebuild the contributor budgets from what survives so the budget
    /// recovers. `visible` may arrive in any order; entries never overlap,
    /// so each ledger entry is checked against the visible set with a binary
    /// search plus a bounded backward walk.
    pub fn retain_visible(&mut self, visible: &[(u32, u32, u32)]) {
        let mut ordered: Vec<(u32, u32, u32)> = visible.to_vec();
        ordered.sort();
        #[cfg(debug_assertions)]
        {
            let mut prev: Option<(u32, u32)> = None;
            for &(client, start, end) in &ordered {
                if let Some((prev_client, prev_end)) = prev {
                    debug_assert!(
                        client != prev_client || start >= prev_end,
                        "visible intervals must not overlap"
                    );
                }
                prev = Some((client, end));
            }
        }
        let mut kept: BTreeMap<(u32, u32), (u32, Owner)> = BTreeMap::new();
        for (key, value) in &self.intervals {
            let (client, start) = *key;
            let (end, _) = *value;
            // First visible triple at or past `(client, end)`: everything
            // from here on starts too late to overlap (same client) or
            // belongs to a later client.
            let at = ordered.partition_point(|&(v_client, v_start, _)| {
                v_client < client || (v_client == client && v_start < end)
            });
            let mut overlaps = false;
            // Walk back over same-client triples starting before `end`;
            // sorted non-overlap means the walk stops at the first triple
            // ending at or before `start` (or a client change).
            for &(v_client, v_start, v_end) in ordered[..at].iter().rev() {
                if v_client != client {
                    break;
                }
                if v_end <= start {
                    break;
                }
                if v_start < end {
                    overlaps = true;
                    break;
                }
            }
            if overlaps {
                kept.insert(*key, value.clone());
            }
        }
        self.intervals = kept;
        self.rebuild_contributor_budgets();
    }
}

/// One visible diff chunk: inserted text with the Yjs item id that starts
/// it. The cut layer produces these from `diff_range` over a scratch clone;
/// each chunk carries its first item's `(client, clock)`, and the builder
/// resolves ownership per UTF-16 unit, so chunks survive intact whether or
/// not yrs ever squashes adjacent items into one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffChunk {
    /// Inserted text of this chunk.
    pub text: String,
    /// Yjs client that inserted the chunk's first item.
    pub client: u32,
    /// Clock of the chunk's first item (UTF-16 units from here).
    pub clock: u32,
}

/// One maximal byte range naming one author-table row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    /// Start offset (UTF-8 bytes, inclusive).
    pub start: usize,
    /// End offset (UTF-8 bytes, exclusive).
    pub end: usize,
    /// Index into [`SpanMap::authors`].
    pub author: usize,
}

/// Per-version span map: the committed body's authorship.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpanMap {
    /// Always [`SPAN_MAP_SCHEMA_VERSION`]; the validator enforces it.
    pub version: u8,
    /// Deduplicated author table. Separate from the version's
    /// `contributors[]` by design: contributors mean activity since the last
    /// cut, while authors name the origin of surviving text.
    pub authors: Vec<Owner>,
    /// Maximal ranges tiling `[0, body.len())` in order.
    pub spans: Vec<Span>,
}

impl SpanMap {
    /// Offset kind of every span range: always [`SPAN_OFFSET_KIND`].
    pub fn offset_kind(&self) -> &'static str {
        SPAN_OFFSET_KIND
    }
}

/// Build the span map for `body` from diff chunks and the ownership ledger.
///
/// Concatenated chunk text must equal `body` (reconstruction check). Every
/// UTF-16 unit of every chunk must resolve to a retained interval; a missing
/// interval fails closed as [`SpanBuildError::UnknownOwner`] — the explicit
/// [`Owner::Unattributed`] author is reserved for intervals stamped that way
/// by legacy unattributed core calls, never a fallback for missing tracking.
/// Chunks split across ownership boundaries become separate spans before
/// adjacent same-author spans coalesce into maximal ranges. Byte offsets
/// follow character boundaries by construction.
pub fn build_span_map(
    body: &str,
    chunks: &[DiffChunk],
    ownership: &OwnershipLedger,
) -> Result<SpanMap, SpanBuildError> {
    let rebuilt: String = chunks.iter().map(|chunk| chunk.text.as_str()).collect();
    if rebuilt != body {
        return Err(SpanBuildError::ReconstructionMismatch);
    }
    let mut authors: Vec<Owner> = Vec::new();
    let mut author_index: HashMap<Owner, usize> = HashMap::new();
    let mut spans: Vec<Span> = Vec::new();
    let mut byte = 0usize;
    // Open run: whether a span is under construction, its author-table
    // index, and its start byte. The per-character step compares integer
    // indices only — never owner strings. Author identity resolves once
    // per interval crossing (tree lookup plus one table interning), and
    // cached intervals skip even that.
    let mut open = false;
    let mut open_index = 0usize;
    let mut open_start = 0usize;
    for chunk in chunks {
        let mut clock = chunk.clock;
        // Cached containing interval: `[cached_start, cached_end)` names
        // `cached_index`. A char fully inside it reuses the index with no
        // lookup and no comparison; crossings re-resolve once each.
        let mut cached_start = 0u32;
        let mut cached_end = 0u32;
        let mut cached_index = 0usize;
        let mut cached = false;
        for ch in chunk.text.chars() {
            let units = ch.len_utf16() as u32;
            if !(cached && clock >= cached_start && clock + units <= cached_end) {
                // Unknown stays fail-closed: see UnknownOwner.
                let (end, owner) = ownership.owner_interval_at(chunk.client, clock).ok_or(
                    SpanBuildError::UnknownOwner {
                        client: chunk.client,
                        clock,
                    },
                )?;
                if clock + units > end {
                    // The char's last unit leaves its interval: confirm it
                    // names the same owner, else the char is split.
                    let last = ownership.owner_at(chunk.client, clock + units - 1).ok_or(
                        SpanBuildError::UnknownOwner {
                            client: chunk.client,
                            clock: clock + units - 1,
                        },
                    )?;
                    if last != owner {
                        return Err(SpanBuildError::SplitChar);
                    }
                }
                cached_index = match author_index.get(owner) {
                    Some(&index) => index,
                    None => {
                        let index = authors.len();
                        authors.push(owner.clone());
                        author_index.insert(owner.clone(), index);
                        index
                    }
                };
                cached_start = clock;
                cached_end = end;
                cached = true;
            }
            if !open || open_index != cached_index {
                if open {
                    spans.push(Span {
                        start: open_start,
                        end: byte,
                        author: open_index,
                    });
                    if spans.len() > MAX_SPAN_MAP_SPANS {
                        return Err(SpanBuildError::TooManySpans);
                    }
                }
                open = true;
                open_index = cached_index;
                open_start = byte;
            }
            byte += ch.len_utf8();
            clock += units;
        }
    }
    if open {
        spans.push(Span {
            start: open_start,
            end: byte,
            author: open_index,
        });
        if spans.len() > MAX_SPAN_MAP_SPANS {
            return Err(SpanBuildError::TooManySpans);
        }
    }
    Ok(SpanMap {
        version: SPAN_MAP_SCHEMA_VERSION,
        authors,
        spans,
    })
}
/// Check a span map against `body`: schema version, span and author caps,
/// exact tiling of `[0, body.len())` with non-empty ranges, maximality
/// (adjacent spans never share an author), character-boundary edges, author
/// references inside the map's own table, and a deduplicated table with no
/// unused rows. No ownership lookup happens here: this validates shape and
/// canonicity, not attribution.
pub fn validate_span_map(map: &SpanMap, body: &str) -> Result<(), SpanBuildError> {
    if map.version != SPAN_MAP_SCHEMA_VERSION {
        return Err(SpanBuildError::BadVersion { found: map.version });
    }
    if map.spans.len() > MAX_SPAN_MAP_SPANS {
        return Err(SpanBuildError::TooManySpans);
    }
    if map.authors.len() > MAX_SPAN_MAP_AUTHORS {
        return Err(SpanBuildError::Malformed);
    }
    let mut seen = HashSet::new();
    for (index, author) in map.authors.iter().enumerate() {
        if !seen.insert(author) {
            return Err(SpanBuildError::DuplicateAuthor { index });
        }
    }
    let mut used = vec![false; map.authors.len()];
    let mut pos = 0usize;
    let mut previous: Option<usize> = None;
    for (index, span) in map.spans.iter().enumerate() {
        if span.start != pos || span.end <= span.start || span.end > body.len() {
            return Err(SpanBuildError::BadTiling { index });
        }
        if !body.is_char_boundary(span.start) || !body.is_char_boundary(span.end) {
            return Err(SpanBuildError::BadCharBoundary { index });
        }
        if span.author >= map.authors.len() {
            return Err(SpanBuildError::BadAuthorRef { index });
        }
        if previous == Some(span.author) {
            return Err(SpanBuildError::NotMaximal { index });
        }
        previous = Some(span.author);
        used[span.author] = true;
        pos = span.end;
    }
    if pos != body.len() {
        return Err(SpanBuildError::BadTiling {
            index: map.spans.len(),
        });
    }
    if let Some(index) = used.iter().position(|used| !used) {
        return Err(SpanBuildError::UnusedAuthor { index });
    }
    Ok(())
}

/// Canonical author-row discriminators in the serialized map.
pub const AUTHOR_PRIOR_VERSION: &str = "prior_version";
pub const AUTHOR_CONTRIBUTOR: &str = "contributor";
pub const AUTHOR_UNATTRIBUTED: &str = "unattributed";

/// Parse the canonical serialized span map back into a [`SpanMap`], for the
/// version-payload validator. Structural failures are [`SpanBuildError::Malformed`];
/// tiling, boundaries and author references are left to [`validate_span_map`].
pub fn parse_span_map(value: &Value) -> Result<SpanMap, SpanBuildError> {
    let malformed = || SpanBuildError::Malformed;
    let object = value.as_object().ok_or_else(malformed)?;
    let version = object
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(malformed)?;
    if version != u64::from(SPAN_MAP_SCHEMA_VERSION) {
        return Err(SpanBuildError::BadVersion {
            found: version as u8,
        });
    }
    if object.get("offset_kind").and_then(Value::as_str) != Some(SPAN_OFFSET_KIND) {
        return Err(SpanBuildError::Malformed);
    }
    let authors_json = object
        .get("authors")
        .and_then(Value::as_array)
        .ok_or_else(malformed)?;
    if authors_json.len() > MAX_SPAN_MAP_AUTHORS {
        return Err(SpanBuildError::Malformed);
    }
    let mut authors = Vec::with_capacity(authors_json.len());
    // Parse-time identity budget: authors carry contributor rows, so bound
    // their aggregate bytes while parsing, before any unbounded work below.
    let mut identity_bytes = 0usize;
    for row in authors_json {
        let row = row.as_object().ok_or_else(malformed)?;
        let kind = row
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(malformed)?;
        authors.push(match kind {
            AUTHOR_PRIOR_VERSION => Owner::PriorVersion,
            AUTHOR_UNATTRIBUTED => Owner::Unattributed,
            AUTHOR_CONTRIBUTOR => {
                // Required fields: missing, empty or wrong-typed refuses.
                let required = |key: &str| {
                    row.get(key)
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                        .ok_or_else(malformed)
                };
                // Optional fields: absent is None, but a present wrong-typed
                // or empty value refuses rather than silently becoming None.
                let optional = |key: &str| match row.get(key) {
                    None => Ok(None),
                    Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
                    _ => Err(SpanBuildError::Malformed),
                };
                let principal = required("principal")?.to_owned();
                let executor_kind = required("executor_kind")?.to_owned();
                let run_key = optional("run_key")?;
                let app = match row.get("app") {
                    None => None,
                    Some(app) => {
                        let app = app.as_object().ok_or_else(malformed)?;
                        if app.len() != 3 {
                            return Err(SpanBuildError::Malformed);
                        }
                        let field = |key: &str| {
                            app.get(key)
                                .and_then(Value::as_str)
                                .filter(|value| !value.is_empty())
                                .ok_or_else(malformed)
                        };
                        Some(AppAttribution {
                            package: field("package")?.to_owned(),
                            version: field("version")?.to_owned(),
                            install_event_id: field("install_event_id")?.to_owned(),
                        })
                    }
                };
                let channel = optional("channel")?;
                let owner = Owner::Contributor(AcknowledgedContributor {
                    principal,
                    executor_kind,
                    run_key,
                    app,
                    channel,
                });
                identity_bytes = identity_bytes.saturating_add(owner.budgeted_bytes());
                if identity_bytes > MAX_RETAINED_OWNER_BYTES {
                    return Err(SpanBuildError::Malformed);
                }
                owner
            }
            _ => return Err(SpanBuildError::Malformed),
        });
    }
    let spans_json = object
        .get("spans")
        .and_then(Value::as_array)
        .ok_or_else(malformed)?;
    if spans_json.len() > MAX_SPAN_MAP_SPANS {
        return Err(SpanBuildError::TooManySpans);
    }
    let mut spans = Vec::with_capacity(spans_json.len());
    for triple in spans_json {
        let triple = triple.as_array().ok_or_else(malformed)?;
        if triple.len() != 3 {
            return Err(SpanBuildError::Malformed);
        }
        let mut numbers = [0usize; 3];
        for (slot, value) in numbers.iter_mut().zip(triple.iter()) {
            // Checked conversion: `as usize` would truncate on 32-bit.
            *slot = usize::try_from(value.as_u64().ok_or_else(malformed)?)
                .map_err(|_| SpanBuildError::Malformed)?;
        }
        spans.push(Span {
            start: numbers[0],
            end: numbers[1],
            author: numbers[2],
        });
    }
    Ok(SpanMap {
        version: SPAN_MAP_SCHEMA_VERSION,
        authors,
        spans,
    })
}

/// Visible clock triples `(client, start_clock, end_clock_exclusive)` for
/// diff chunks: the ownership intervals a cut retains. Chunks arrive in
/// document order with per-item starting ids, so each triple's length is
/// the chunk text measured in UTF-16 units.
pub(crate) fn visible_triples(chunks: &[DiffChunk]) -> Vec<(u32, u32, u32)> {
    chunks
        .iter()
        .map(|chunk| {
            let units: u32 = chunk.text.chars().map(|ch| ch.len_utf16() as u32).sum();
            (chunk.client, chunk.clock, chunk.clock + units)
        })
        .collect()
}

/// Canonical serialized span map: version, byte offset kind, the distinct
/// author table, and maximal ranges as compact integer triples. Shared by
/// the version-payload assembler and the prospective budget check.
pub(crate) fn serialize_span_map(map: &SpanMap) -> Value {
    use serde_json::{json, Map};
    let mut authors = Vec::with_capacity(map.authors.len());
    for author in &map.authors {
        authors.push(match author {
            Owner::PriorVersion => json!({"type": AUTHOR_PRIOR_VERSION}),
            Owner::Unattributed => json!({"type": AUTHOR_UNATTRIBUTED}),
            Owner::Contributor(fact) => {
                let mut row = Map::new();
                row.insert("type".into(), Value::String(AUTHOR_CONTRIBUTOR.into()));
                row.insert("principal".into(), Value::String(fact.principal.clone()));
                row.insert(
                    "executor_kind".into(),
                    Value::String(fact.executor_kind.clone()),
                );
                if let Some(run_key) = fact.run_key.as_ref() {
                    row.insert("run_key".into(), Value::String(run_key.clone()));
                }
                if let Some(app) = fact.app.as_ref() {
                    row.insert(
                        "app".into(),
                        json!({
                            "package": app.package,
                            "version": app.version,
                            "install_event_id": app.install_event_id,
                        }),
                    );
                }
                if let Some(channel) = fact.channel.as_ref() {
                    row.insert("channel".into(), Value::String(channel.clone()));
                }
                Value::Object(row)
            }
        });
    }
    let spans: Vec<Value> = map
        .spans
        .iter()
        .map(|span| json!([span.start, span.end, span.author]))
        .collect();
    json!({
        "version": SPAN_MAP_SCHEMA_VERSION,
        "offset_kind": SPAN_OFFSET_KIND,
        "authors": authors,
        "spans": spans,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use yrs::ClientID;
    fn contributor(principal: &str) -> Owner {
        Owner::Contributor(AcknowledgedContributor {
            principal: principal.into(),
            executor_kind: "human".into(),
            run_key: None,
            app: None,
            channel: None,
        })
    }

    fn advance(ledger: &mut OwnershipLedger, client: u32, start: u32, end: u32, owner: &Owner) {
        let mut before = StateVector::default();
        if start > 0 {
            before.set_max(ClientID::new(u64::from(client)), start);
        }
        let mut after = StateVector::default();
        after.set_max(ClientID::new(u64::from(client)), end);
        ledger.record_advance(&before, &after, owner).unwrap();
    }

    #[test]
    fn interleave_coalesces_into_maximal_ranges() {
        let alice = contributor("alice");
        let bob = contributor("bob");
        let mut ledger = OwnershipLedger::new();
        advance(&mut ledger, 2, 0, 5, &Owner::PriorVersion);
        advance(&mut ledger, 2, 5, 8, &alice);
        advance(&mut ledger, 3, 0, 3, &bob);
        let chunks = vec![
            DiffChunk {
                text: "hello".into(),
                client: 2,
                clock: 0,
            },
            DiffChunk {
                text: "XY".into(),
                client: 2,
                clock: 5,
            },
            DiffChunk {
                text: "Z".into(),
                client: 2,
                clock: 7,
            },
            DiffChunk {
                text: "!?#".into(),
                client: 3,
                clock: 0,
            },
        ];
        let map = build_span_map("helloXYZ!?#", &chunks, &ledger).unwrap();
        assert_eq!(map.version, SPAN_MAP_SCHEMA_VERSION);
        assert_eq!(map.offset_kind(), "bytes");
        assert_eq!(
            map.authors,
            vec![Owner::PriorVersion, alice.clone(), bob.clone()]
        );
        assert_eq!(
            map.spans,
            vec![
                Span {
                    start: 0,
                    end: 5,
                    author: 0
                },
                Span {
                    start: 5,
                    end: 8,
                    author: 1
                },
                Span {
                    start: 8,
                    end: 11,
                    author: 2
                },
            ]
        );
        validate_span_map(&map, "helloXYZ!?#").unwrap();
    }

    #[test]
    fn squashed_chunk_splits_across_ownership() {
        let alice = contributor("alice");
        let mut ledger = OwnershipLedger::new();
        advance(&mut ledger, 2, 0, 2, &Owner::PriorVersion);
        advance(&mut ledger, 2, 2, 4, &alice);
        // One chunk spanning two intervals: the builder still splits.
        let chunks = vec![DiffChunk {
            text: "abcd".into(),
            client: 2,
            clock: 0,
        }];
        let map = build_span_map("abcd", &chunks, &ledger).unwrap();
        assert_eq!(
            map.spans,
            vec![
                Span {
                    start: 0,
                    end: 2,
                    author: 0
                },
                Span {
                    start: 2,
                    end: 4,
                    author: 1
                },
            ]
        );
    }

    #[test]
    fn unknown_owner_refuses_instead_of_guessing() {
        let ledger = OwnershipLedger::new();
        let chunks = vec![DiffChunk {
            text: "hi".into(),
            client: 2,
            clock: 0,
        }];
        assert_eq!(
            build_span_map("hi", &chunks, &ledger),
            Err(SpanBuildError::UnknownOwner {
                client: 2,
                clock: 0
            })
        );
    }

    #[test]
    fn reconstruction_mismatch_refuses() {
        let mut ledger = OwnershipLedger::new();
        advance(&mut ledger, 2, 0, 2, &Owner::PriorVersion);
        let chunks = vec![DiffChunk {
            text: "hi".into(),
            client: 2,
            clock: 0,
        }];
        assert_eq!(
            build_span_map("bye", &chunks, &ledger),
            Err(SpanBuildError::ReconstructionMismatch)
        );
    }

    #[test]
    fn emoji_byte_offsets_follow_utf16_clocks() {
        // "é" is 2 bytes / 1 unit; "🎉" is 4 bytes / 2 units.
        let alice = contributor("alice");
        let mut ledger = OwnershipLedger::new();
        advance(&mut ledger, 2, 0, 1, &Owner::PriorVersion);
        advance(&mut ledger, 2, 1, 3, &alice);
        let chunks = vec![DiffChunk {
            text: "é🎉".into(),
            client: 2,
            clock: 0,
        }];
        let map = build_span_map("é🎉", &chunks, &ledger).unwrap();
        assert_eq!(
            map.spans,
            vec![
                Span {
                    start: 0,
                    end: 2,
                    author: 0
                },
                Span {
                    start: 2,
                    end: 6,
                    author: 1
                },
            ]
        );
        validate_span_map(&map, "é🎉").unwrap();
    }

    #[test]
    fn validator_rejects_non_maximal_duplicate_and_unused_authors() {
        let alice = contributor("alice");
        let base = SpanMap {
            version: SPAN_MAP_SCHEMA_VERSION,
            authors: vec![alice.clone()],
            spans: vec![Span {
                start: 0,
                end: 3,
                author: 0,
            }],
        };
        // Adjacent same-author spans are not maximal.
        let split = SpanMap {
            spans: vec![
                Span {
                    start: 0,
                    end: 1,
                    author: 0,
                },
                Span {
                    start: 1,
                    end: 3,
                    author: 0,
                },
            ],
            ..base.clone()
        };
        assert_eq!(
            validate_span_map(&split, "abc"),
            Err(SpanBuildError::NotMaximal { index: 1 })
        );
        // Duplicate author rows are not deduplicated.
        let duplicated = SpanMap {
            authors: vec![alice.clone(), alice.clone()],
            ..base.clone()
        };
        assert_eq!(
            validate_span_map(&duplicated, "abc"),
            Err(SpanBuildError::DuplicateAuthor { index: 1 })
        );
        // Unreferenced rows are not allowed.
        let unused = SpanMap {
            authors: vec![alice.clone(), Owner::PriorVersion],
            ..base.clone()
        };
        assert_eq!(
            validate_span_map(&unused, "abc"),
            Err(SpanBuildError::UnusedAuthor { index: 1 })
        );
    }

    #[test]
    fn empty_body_maps_empty() {
        let ledger = OwnershipLedger::new();
        let map = build_span_map("", &[], &ledger).unwrap();
        assert!(map.spans.is_empty() && map.authors.is_empty());
        validate_span_map(&map, "").unwrap();
    }

    #[test]
    fn validator_rejects_bad_maps() {
        let alice = contributor("alice");
        let good = SpanMap {
            version: SPAN_MAP_SCHEMA_VERSION,
            authors: vec![alice],
            spans: vec![Span {
                start: 0,
                end: 3,
                author: 0,
            }],
        };
        validate_span_map(&good, "abc").unwrap();
        let bad_version = SpanMap {
            version: 0,
            ..good.clone()
        };
        assert_eq!(
            validate_span_map(&bad_version, "abc"),
            Err(SpanBuildError::BadVersion { found: 0 })
        );
        let gap = SpanMap {
            spans: vec![
                Span {
                    start: 0,
                    end: 1,
                    author: 0,
                },
                Span {
                    start: 2,
                    end: 3,
                    author: 0,
                },
            ],
            ..good.clone()
        };
        assert_eq!(
            validate_span_map(&gap, "abc"),
            Err(SpanBuildError::BadTiling { index: 1 })
        );
        let bad_ref = SpanMap {
            spans: vec![Span {
                start: 0,
                end: 3,
                author: 1,
            }],
            ..good.clone()
        };
        assert_eq!(
            validate_span_map(&bad_ref, "abc"),
            Err(SpanBuildError::BadAuthorRef { index: 0 })
        );
        // Mid-char edge on "é" (2 bytes): end 1 is not a boundary.
        let bad_edge = SpanMap {
            spans: vec![Span {
                start: 0,
                end: 1,
                author: 0,
            }],
            ..good.clone()
        };
        assert_eq!(
            validate_span_map(&bad_edge, "é"),
            Err(SpanBuildError::BadCharBoundary { index: 0 })
        );
    }

    #[test]
    fn contiguous_same_owner_advances_coalesce() {
        let alice = contributor("alice");
        let mut ledger = OwnershipLedger::new();
        advance(&mut ledger, 2, 0, 2, &alice);
        advance(&mut ledger, 2, 2, 5, &alice);
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.owner_at(2, 4), Some(&alice));
    }

    #[test]
    fn budgets_refuse_before_mutation() {
        let mut ledger = OwnershipLedger::new();
        let alice = contributor("alice");
        advance(&mut ledger, 2, 0, MAX_OWNERSHIP_INTERVALS as u32, &alice);
        // Clock space is contiguous and coalesced, so this fits: one interval.
        assert_eq!(ledger.len(), 1);
        // Distinct clients each add an interval; the 32769th refuses.
        let mut ledger = OwnershipLedger::new();
        for client in 0..MAX_OWNERSHIP_INTERVALS as u32 {
            advance(&mut ledger, client, 0, 1, &alice);
        }
        assert_eq!(ledger.len(), MAX_OWNERSHIP_INTERVALS);
        let mut before = StateVector::default();
        before.set_max(ClientID::new(u64::from(MAX_OWNERSHIP_INTERVALS as u32)), 0);
        let mut after = StateVector::default();
        after.set_max(ClientID::new(u64::from(MAX_OWNERSHIP_INTERVALS as u32)), 1);
        assert_eq!(
            ledger.record_advance(&before, &after, &alice),
            Err(OwnershipError::BudgetExhausted)
        );
        // Failed advance mutated nothing.
        assert_eq!(ledger.len(), MAX_OWNERSHIP_INTERVALS);
    }

    #[test]
    fn retain_visible_prunes_deleted_and_recovers_budget() {
        let alice = contributor("alice");
        let bob = contributor("bob");
        let mut ledger = OwnershipLedger::new();
        advance(&mut ledger, 2, 0, 4, &alice);
        advance(&mut ledger, 3, 0, 4, &bob);
        assert_eq!(ledger.contributor_count(), 2);
        // Only alice's first half survives the cut.
        ledger.retain_visible(&[(2, 0, 2)]);
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.contributor_count(), 1);
        assert_eq!(ledger.owner_at(2, 1), Some(&alice));
        assert_eq!(ledger.owner_at(3, 0), None);
    }

    /// End-to-end across the real yrs boundary: three client ids (seed,
    /// peer, reused-style server author) with Unicode text, enumerated with
    /// public `diff_range` on a scratch clone and mapped to byte spans.
    #[test]
    fn real_doc_diff_chunks_map_across_clients_and_unicode() {
        use yrs::types::text::{ChangeKind, YChange};
        use yrs::updates::decoder::Decode;
        use yrs::{Any, Doc, GetString, Out, ReadTxn, Snapshot, Text, Transact, Update};

        fn doc_for(client: u64) -> Doc {
            let mut options = yrs::Options::with_client_id(yrs::ClientID::new(client));
            options.offset_kind = yrs::OffsetKind::Bytes;
            Doc::with_options(options)
        }
        fn full_state(doc: &Doc) -> Vec<u8> {
            doc.transact()
                .encode_state_as_update_v1(&yrs::StateVector::default())
        }
        fn apply_full(target: &Doc, state: &[u8]) {
            let _ = target.get_or_insert_text("body");
            let mut txn = target.transact_mut();
            txn.apply_update(Update::decode_v1(state).unwrap()).unwrap();
        }

        let seed = doc_for(7);
        {
            let text = seed.get_or_insert_text("body");
            let mut txn = seed.transact_mut();
            text.insert(&mut txn, 0, "aé");
        }
        let peer = doc_for(8);
        apply_full(&peer, &full_state(&seed));
        {
            let text = peer.get_or_insert_text("body");
            let mut txn = peer.transact_mut();
            text.insert(&mut txn, 3, "🎉");
        }
        let server = doc_for(9);
        apply_full(&server, &full_state(&peer));
        {
            let text = server.get_or_insert_text("body");
            let mut txn = server.transact_mut();
            text.insert(&mut txn, 0, "Z");
        }
        assert_eq!(
            server
                .get_or_insert_text("body")
                .get_string(&server.transact()),
            "Zaé🎉"
        );

        // Scratch clone: enumeration must never mutate the live doc.
        let scratch = doc_for(999);
        apply_full(&scratch, &full_state(&server));
        let body = scratch
            .get_or_insert_text("body")
            .get_string(&scratch.transact());
        let hi = scratch.transact().snapshot();
        let lo = Snapshot::default();
        let diffs = {
            let text = scratch.get_or_insert_text("body");
            let mut txn = scratch.transact_mut();
            text.diff_range(&mut txn, Some(&hi), Some(&lo), YChange::identity)
        };
        let mut chunks = Vec::new();
        for diff in &diffs {
            let change = diff
                .ychange
                .as_ref()
                .expect("every chunk carries its inserter");
            assert_eq!(change.kind, ChangeKind::Added);
            match &diff.insert {
                Out::Any(Any::String(text)) => chunks.push(DiffChunk {
                    text: text.to_string(),
                    client: u32::try_from(change.id.client.get()).unwrap(),
                    clock: change.id.clock,
                }),
                other => panic!("plain-text doc yields string chunks, got {other:?}"),
            }
        }
        assert_eq!(
            chunks
                .iter()
                .map(|chunk| chunk.text.as_str())
                .collect::<String>(),
            body
        );

        let bob = contributor("bob");
        let alice = contributor("alice");
        let mut ledger = OwnershipLedger::new();
        advance(&mut ledger, 7, 0, 2, &Owner::PriorVersion);
        advance(&mut ledger, 8, 0, 2, &alice);
        advance(&mut ledger, 9, 0, 1, &bob);
        let map = build_span_map(&body, &chunks, &ledger).unwrap();
        assert_eq!(
            map.authors,
            vec![bob.clone(), Owner::PriorVersion, alice.clone()]
        );
        assert_eq!(
            map.spans,
            vec![
                Span {
                    start: 0,
                    end: 1,
                    author: 0
                },
                Span {
                    start: 1,
                    end: 4,
                    author: 1
                },
                Span {
                    start: 4,
                    end: 8,
                    author: 2
                },
            ]
        );
        validate_span_map(&map, &body).unwrap();
    }
}
