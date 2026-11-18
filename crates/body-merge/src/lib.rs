//! Three-way body merge: a 1:1 Rust port of the browser kit's text rebase
//! (`web/apps/src/kit/coedit/pendingIntent.ts`: `diffRegions`, `charRegions`,
//! `myersOps`, `hunkOverlapsRegion`, `shiftBefore`, `rebaseHunks`, with the
//! surrogate-safe `prefixSuffixDiff` of `splice.ts`).
//!
//! Pure: strings in, strings out. No database, session or async. The engine
//! calls it through the root compatibility re-export (`src/coedit/body_merge.rs`):
//! the home `merge_body` operation (`src/mcp/tools/merge_body.rs`) and durable
//! per-editor lineage (`src/node/lineage.rs`). Design:
//! `docs/design/body-merge-home.md`.
//!
//! **Units.** Every offset in this module is a Unicode *scalar* index (an index
//! into the string's `char`s), not a byte offset and not a UTF-16 unit. The TS
//! kit counts UTF-16 units but snaps every diff edge to a code-point boundary,
//! so the two describe the same edges and differ only in unit. The shared
//! vectors (`protocol/vectors/body-merge/`) record scalar offsets and both
//! suites run them.
//!
//! **Do not build this on `text_diff` splices.** It is a different
//! algorithm (bytes; line diff only, so two edits on one line stay one splice;
//! different caps). The merge must reproduce the kit exactly so a remote change
//! clashes or not independently of which side ran the diff.
//!
//! **No agreement or extension rule.** Identical changes on both sides clash
//! exactly as the kit does today.
//!
//! Caps, with their different scopes (kept from the TS):
//! * line level: more than [`LINE_TOKEN_CAP`] lines (both sides together) or a
//!   line edit distance over [`LINE_EDIT_CAP`] makes the **whole middle** one
//!   outer span;
//! * character level, inside one replaced line block only: more than
//!   [`CHAR_TOKEN_CAP`] scalars (both sides of that block together) or an edit
//!   distance over [`CHAR_EDIT_CAP`] makes **that one line block** a single
//!   region; every other region stays intact.

// Test-only helpers (`Region`, `Rebased`, `diff_regions`, `rebase_hunks`,
// `apply_hunks`) carry a scoped `#[allow(dead_code)]` each: the `cfg(test)`
// vector suite below is their only caller, and non-test builds must stay
// warning-free (clippy runs `-D warnings`).

use std::collections::HashMap;

/// Line-level cap on `lines(base middle) + lines(theirs middle)`.
const LINE_TOKEN_CAP: usize = 20_000;
/// Line-level Myers edit-distance cap.
const LINE_EDIT_CAP: usize = 1000;
/// Character-level cap on scalars of one replaced block, both sides together.
const CHAR_TOKEN_CAP: usize = 40_000;
/// Character-level Myers edit-distance cap.
const CHAR_EDIT_CAP: usize = 400;

/// Replace `del` scalars at `index` of the **base** with `insert`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hunk {
    pub index: usize,
    pub del: usize,
    pub insert: String,
}

/// One changed span between base and theirs. A pure insert has an empty base
/// span; a pure delete has an empty theirs span. Ordered, non-overlapping,
/// scalar indexes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
struct Region {
    pub base_start: usize,
    pub base_end: usize,
    pub theirs_start: usize,
    pub theirs_end: usize,
}

/// A pending edit that could not be placed because it touches a remote change.
/// `base` is the passage before the person's edit, `mine` what they made of it,
/// `theirs` what that passage is now (`""` for a deleted passage); the theirs
/// offsets locate it in the text the merge ran against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clash {
    pub base_start: usize,
    pub base_end: usize,
    pub base: String,
    pub mine: String,
    pub theirs: String,
    pub theirs_start: usize,
    pub theirs_end: usize,
}

/// Result of [`rebase_hunks`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
struct Rebased {
    /// Hunks that landed, in `theirs` coordinates, in input order.
    pub placed: Vec<Hunk>,
    /// Overlapping hunks, merged with the regions they touch; not applied.
    pub clashes: Vec<Clash>,
    /// Only the text inserted by clashing hunks, in order (no base context).
    pub draft: String,
    /// Total base scalars deleted by clashing hunks.
    pub unreplayed_deletes: usize,
}

/// A clash located in the **merged** text as well as in `theirs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedClash {
    pub clash: Clash,
    /// Start of the clash passage in `BodyMerge::merged`: `theirs_start`
    /// shifted by the placed hunks before it. `merged[at_start..at_end]` is the
    /// clash's `theirs` text, untouched.
    pub at_start: usize,
    pub at_end: usize,
}

/// Result of [`merge_bodies`] / [`merge_hunks`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyMerge {
    /// `theirs` with the placed hunks applied.
    pub merged: String,
    /// Placed hunks in `theirs` coordinates, in input order.
    pub placed: Vec<Hunk>,
    /// Clashes in span order. Not applied: `theirs` stays as it is there.
    pub clashes: Vec<MergedClash>,
}

fn chars_of(s: &str) -> Vec<char> {
    s.chars().collect()
}

/// `text[from..to]` clamped like JS `slice` (never panics; empty if inverted).
fn slice(text: &[char], from: usize, to: usize) -> String {
    let to = to.min(text.len());
    let from = from.min(to);
    text[from..to].iter().collect()
}

/// Common prefix/suffix of `a` and `b`. Reassembles both inputs exactly:
/// `a[..start] == b[..start]` and `a[end_a..] == b[end_b..]`. Surrogate
/// back-off is unnecessary in scalars: an edge can never split a character.
struct StringDiff {
    start: usize,
    end_a: usize,
    end_b: usize,
}

fn prefix_suffix_diff(a: &[char], b: &[char]) -> StringDiff {
    let max = a.len().min(b.len());
    let mut start = 0;
    while start < max && a[start] == b[start] {
        start += 1;
    }
    let tail_max = (a.len() - start).min(b.len() - start);
    let mut suffix = 0;
    while suffix < tail_max && a[a.len() - 1 - suffix] == b[b.len() - 1 - suffix] {
        suffix += 1;
    }
    StringDiff {
        start,
        end_a: a.len() - suffix,
        end_b: b.len() - suffix,
    }
}

/// Adjacency rule for placement. A hunk that only *touches* a region (meets it
/// at an edge without entering it) is placed, not clashed. The one exception is
/// two pure inserts at exactly the same base point: neither comes first, so
/// they clash.
fn hunk_overlaps_region(h: &Hunk, r: &Region) -> bool {
    let empty_h = h.del == 0;
    let empty_r = r.base_start == r.base_end;
    if !empty_h && !empty_r {
        h.index < r.base_end && h.index + h.del > r.base_start
    } else if empty_h && !empty_r {
        r.base_start < h.index && h.index < r.base_end
    } else if !empty_h && empty_r {
        h.index < r.base_start && r.base_start < h.index + h.del
    } else {
        h.index == r.base_start
    }
}

// Test-only work counter: region and hunk visits, binary-search probes and
// insertion-length scans made by the rebase and clash-coordinate lookups. Per
// thread, so parallel tests do not disturb each other.
#[cfg(test)]
thread_local! {
    static REGION_WORK: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[inline]
fn count_work() {
    count_work_n(1);
}

#[inline]
fn count_work_n(_n: usize) {
    #[cfg(test)]
    REGION_WORK.with(|w| w.set(w.get() + _n));
}

/// Regions with their cumulative base→theirs shifts precomputed, so each
/// lookup is a binary search instead of a scan from the start. Regions are
/// ordered and strictly separated, so `base_start` and `base_end` are both
/// non-decreasing and the lookups below return exactly what the TS scans find.
struct RegionIndex<'a> {
    regions: &'a [Region],
    /// `cum[i]` = total shift of `regions[..i]`.
    cum: Vec<isize>,
}

impl<'a> RegionIndex<'a> {
    fn new(regions: &'a [Region]) -> Self {
        let mut cum = Vec::with_capacity(regions.len() + 1);
        let mut shift = 0isize;
        cum.push(shift);
        for r in regions {
            shift +=
                (r.theirs_end - r.theirs_start) as isize - (r.base_end - r.base_start) as isize;
            cum.push(shift);
        }
        RegionIndex { regions, cum }
    }

    /// Cumulative base→theirs shift for an offset `x`: regions ending exactly
    /// at `x` count as before it (TS `shiftBefore`).
    fn shift_before(&self, x: usize) -> isize {
        self.cum[self.regions.partition_point(|r| {
            count_work();
            r.base_end <= x
        })]
    }

    /// Index of the first region that can overlap a hunk starting at `index`
    /// (every overlap rule needs `region.base_end >= index`).
    fn first_candidate(&self, index: usize) -> usize {
        self.regions.partition_point(|r| {
            count_work();
            r.base_end < index
        })
    }

    /// Regions that are empty on the base side at exactly `point`.
    fn inserts_at(&self, point: usize) -> impl Iterator<Item = &Region> {
        let from = self.regions.partition_point(|r| {
            count_work();
            r.base_start < point
        });
        self.regions[from..]
            .iter()
            .take_while(move |r| r.base_start == point)
            .filter(move |r| r.base_end == point)
    }
}

fn offset(x: usize, shift: isize) -> usize {
    (x as isize + shift) as usize
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Equal,
    Delete,
    Insert,
}

/// Greedy Myers (O(ND)) over token ids, forward order. `None` when either side
/// is empty or the edit distance exceeds `d_cap`. Trace rows are narrow slices
/// (width `2d + 1`), so memory stays O(D²).
fn myers_ops(a: &[u32], b: &[u32], d_cap: usize) -> Option<Vec<Op>> {
    let n = a.len() as isize;
    let m = b.len() as isize;
    if n == 0 || m == 0 {
        return None;
    }
    let max = n + m;
    let cap = max.min(d_cap as isize);
    let off = max;
    let mut v = vec![0isize; (2 * max + 1) as usize];
    let mut trace: Vec<Vec<isize>> = Vec::new();
    let mut found: isize = -1;
    let mut d = 0isize;
    while d <= cap {
        let mut k = -d;
        while k <= d {
            let mut x =
                if k == -d || (k != d && v[(off + k - 1) as usize] < v[(off + k + 1) as usize]) {
                    v[(off + k + 1) as usize]
                } else {
                    v[(off + k - 1) as usize] + 1
                };
            let mut y = x - k;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[(off + k) as usize] = x;
            if x >= n && y >= m {
                found = d;
                break;
            }
            k += 2;
        }
        trace.push(v[(off - d) as usize..(off + d + 1) as usize].to_vec());
        if found >= 0 {
            break;
        }
        d += 1;
    }
    if found < 0 {
        return None;
    }
    let mut ops: Vec<Op> = Vec::new();
    let mut x = n;
    let mut y = m;
    let mut d = found;
    while d > 0 {
        let vp = &trace[(d - 1) as usize];
        let at = |kk: isize| -> isize { vp[(kk + d - 1) as usize] };
        let k = x - y;
        let prev_k = if k == -d || (k != d && at(k - 1) < at(k + 1)) {
            k + 1
        } else {
            k - 1
        };
        let prev_x = at(prev_k);
        let prev_y = prev_x - prev_k;
        while x > prev_x && y > prev_y {
            ops.push(Op::Equal);
            x -= 1;
            y -= 1;
        }
        // (The TS also steps x/y here before jumping to the previous point.)
        ops.push(if x == prev_x { Op::Insert } else { Op::Delete });
        x = prev_x;
        y = prev_y;
        d -= 1;
    }
    while x > 0 && y > 0 {
        ops.push(Op::Equal);
        x -= 1;
        y -= 1;
    }
    ops.reverse();
    Some(ops)
}

/// Lines of `s`, each keeping its trailing `\n`; a final unterminated line is
/// kept too. Returned as `(start, end)` scalar ranges.
fn split_lines(s: &[char]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, c) in s.iter().enumerate() {
        if *c == '\n' {
            out.push((start, i + 1));
            start = i + 1;
        }
    }
    if start < s.len() {
        out.push((start, s.len()));
    }
    out
}

/// Character-level regions for one changed span, or `None` when it is empty on
/// one side or too large / too distant to diff exactly.
fn char_regions(
    a_text: &[char],
    b_text: &[char],
    a_base: usize,
    b_base: usize,
) -> Option<Vec<Region>> {
    if a_text.is_empty() || b_text.is_empty() {
        return None;
    }
    if a_text.len() + b_text.len() > CHAR_TOKEN_CAP {
        return None;
    }
    let a: Vec<u32> = a_text.iter().map(|c| *c as u32).collect();
    let b: Vec<u32> = b_text.iter().map(|c| *c as u32).collect();
    let ops = myers_ops(&a, &b, CHAR_EDIT_CAP)?;
    let mut regions = Vec::new();
    let (mut ai, mut bi) = (0usize, 0usize);
    let mut open: Option<(usize, usize)> = None;
    let mut flush = |open: &mut Option<(usize, usize)>, ai: usize, bi: usize| {
        if let Some((a0, b0)) = open.take() {
            regions.push(Region {
                base_start: a_base + a0,
                base_end: a_base + ai,
                theirs_start: b_base + b0,
                theirs_end: b_base + bi,
            });
        }
    };
    for op in ops {
        if op == Op::Equal {
            flush(&mut open, ai, bi);
            ai += 1;
            bi += 1;
        } else {
            if open.is_none() {
                open = Some((ai, bi));
            }
            if op == Op::Delete {
                ai += 1;
            } else {
                bi += 1;
            }
        }
    }
    flush(&mut open, ai, bi);
    Some(regions)
}

fn diff_regions_chars(base: &[char], theirs: &[char]) -> Vec<Region> {
    let outer = prefix_suffix_diff(base, theirs);
    if outer.start == outer.end_a && outer.start == outer.end_b {
        return Vec::new();
    }
    let single = Region {
        base_start: outer.start,
        base_end: outer.end_a,
        theirs_start: outer.start,
        theirs_end: outer.end_b,
    };
    let mid_a = &base[outer.start..outer.end_a];
    let mid_b = &theirs[outer.start..outer.end_b];
    if mid_a.is_empty() || mid_b.is_empty() {
        return vec![single];
    }
    let a_lines = split_lines(mid_a);
    let b_lines = split_lines(mid_b);
    if a_lines.len() + b_lines.len() > LINE_TOKEN_CAP {
        return vec![single];
    }
    let mut table: HashMap<&[char], u32> = HashMap::new();
    let a_ids: Vec<u32> = a_lines
        .iter()
        .map(|&(s, e)| {
            let line = &mid_a[s..e];
            let next = table.len() as u32;
            *table.entry(line).or_insert(next)
        })
        .collect();
    let b_ids: Vec<u32> = b_lines
        .iter()
        .map(|&(s, e)| {
            let line = &mid_b[s..e];
            let next = table.len() as u32;
            *table.entry(line).or_insert(next)
        })
        .collect();
    let Some(ops) = myers_ops(&a_ids, &b_ids, LINE_EDIT_CAP) else {
        return vec![single];
    };
    let mut a_starts = vec![0usize];
    for &(s, e) in &a_lines {
        a_starts.push(a_starts[a_starts.len() - 1] + (e - s));
    }
    let mut b_starts = vec![0usize];
    for &(s, e) in &b_lines {
        b_starts.push(b_starts[b_starts.len() - 1] + (e - s));
    }
    let mut regions = Vec::new();
    let (mut ai, mut bi) = (0usize, 0usize);
    let mut open: Option<(usize, usize)> = None;
    let mut flush = |open: &mut Option<(usize, usize)>, ai: usize, bi: usize| {
        let Some((a0, b0)) = open.take() else { return };
        let (a_u0, a_u1) = (a_starts[a0], a_starts[ai]);
        let (b_u0, b_u1) = (b_starts[b0], b_starts[bi]);
        let whole = Region {
            base_start: outer.start + a_u0,
            base_end: outer.start + a_u1,
            theirs_start: outer.start + b_u0,
            theirs_end: outer.start + b_u1,
        };
        if a0 == ai || b0 == bi {
            regions.push(whole);
            return;
        }
        match char_regions(
            &mid_a[a_u0..a_u1],
            &mid_b[b_u0..b_u1],
            outer.start + a_u0,
            outer.start + b_u0,
        ) {
            Some(sub) => regions.extend(sub),
            None => regions.push(whole),
        }
    };
    for op in ops {
        if op == Op::Equal {
            flush(&mut open, ai, bi);
            ai += 1;
            bi += 1;
        } else {
            if open.is_none() {
                open = Some((ai, bi));
            }
            if op == Op::Delete {
                ai += 1;
            } else {
                bi += 1;
            }
        }
    }
    flush(&mut open, ai, bi);
    regions
}

/// Base→theirs changes as separate ordered non-overlapping regions: the outer
/// prefix/suffix span, refined line-first inside, then by character inside each
/// replaced line block. See the module docs for the cap fallbacks.
#[allow(dead_code)]
fn diff_regions(base: &str, theirs: &str) -> Vec<Region> {
    diff_regions_chars(&chars_of(base), &chars_of(theirs))
}

/// Hunks turning `base` into `mine`: one per [`diff_regions`] region, as
/// `{index: base_start, del: base_end - base_start, insert: mine[theirs span]}`.
/// This is the home-side stand-in for the kit's Yjs-derived intent; it can
/// classify an ambiguous edit differently (design 1.3, vector item 11).
pub fn hunks_between(base: &str, mine: &str) -> Vec<Hunk> {
    hunks_between_chars(&chars_of(base), &chars_of(mine))
}

fn hunks_between_chars(base: &[char], mine: &[char]) -> Vec<Hunk> {
    diff_regions_chars(base, mine)
        .into_iter()
        .map(|r| Hunk {
            index: r.base_start,
            del: r.base_end - r.base_start,
            insert: slice(mine, r.theirs_start, r.theirs_end),
        })
        .collect()
}

struct RebaseCore {
    rebased: Rebased,
    /// For each `rebased.placed[i]`, the index of its source hunk.
    placed_from: Vec<usize>,
}

fn rebase_core(hunks: &[Hunk], base: &[char], theirs: &[char]) -> RebaseCore {
    let regions = diff_regions_chars(base, theirs);
    let index = RegionIndex::new(&regions);
    let mut placed = Vec::new();
    let mut placed_from = Vec::new();
    struct Span {
        start: usize,
        end: usize,
        hunk: usize,
    }
    let mut spans: Vec<Span> = Vec::new();
    let mut unreplayed_deletes = 0;
    for (hi, h) in hunks.iter().enumerate() {
        let mut start = h.index;
        let mut end = h.index + h.del;
        let mut hit = false;
        for r in &regions[index.first_candidate(h.index)..] {
            count_work();
            if r.base_start > end {
                break;
            }
            if !hunk_overlaps_region(h, r) {
                continue;
            }
            hit = true;
            if r.base_start < start {
                start = r.base_start;
            }
            if r.base_end > end {
                end = r.base_end;
            }
        }
        if !hit {
            placed.push(Hunk {
                index: offset(h.index, index.shift_before(h.index)),
                del: h.del,
                insert: h.insert.clone(),
            });
            placed_from.push(hi);
        } else {
            spans.push(Span {
                start,
                end,
                hunk: hi,
            });
            unreplayed_deletes += h.del;
        }
    }
    let clashing: Vec<usize> = spans.iter().map(|s| s.hunk).collect();
    // Merge overlapping or adjacent clashing spans into one clash each.
    spans.sort_by(|a, b| a.start.cmp(&b.start).then(a.end.cmp(&b.end)));
    let mut clashes = Vec::new();
    let mut i = 0;
    while i < spans.len() {
        let cs = spans[i].start;
        let mut ce = spans[i].end;
        let mut group = vec![spans[i].hunk];
        i += 1;
        while i < spans.len() && spans[i].start <= ce {
            if spans[i].end > ce {
                ce = spans[i].end;
            }
            group.push(spans[i].hunk);
            i += 1;
        }
        group.sort_by(|&a, &b| {
            hunks[a]
                .index
                .cmp(&hunks[b].index)
                .then(hunks[a].del.cmp(&hunks[b].del))
        });
        let mut mine = String::new();
        let mut pos = cs;
        for &gi in &group {
            let h = &hunks[gi];
            mine.push_str(&slice(base, pos, h.index));
            mine.push_str(&h.insert);
            pos = h.index + h.del;
        }
        mine.push_str(&slice(base, pos, ce));
        let (theirs_start, theirs_end) = if cs == ce {
            // Same-point pure inserts: theirs is the remote insert at that point.
            let mut found: Option<(usize, usize)> = None;
            for r in index.inserts_at(cs) {
                found = Some(match found {
                    None => (r.theirs_start, r.theirs_end),
                    Some((s, e)) => (s.min(r.theirs_start), e.max(r.theirs_end)),
                });
            }
            found.unwrap_or_else(|| {
                let p = offset(cs, index.shift_before(cs));
                (p, p)
            })
        } else {
            (
                offset(cs, index.shift_before(cs)),
                offset(ce, index.shift_before(ce)),
            )
        };
        clashes.push(Clash {
            base_start: cs,
            base_end: ce,
            base: slice(base, cs, ce),
            mine,
            theirs: slice(theirs, theirs_start, theirs_end),
            theirs_start,
            theirs_end,
        });
    }
    let mut ordered = clashing;
    ordered.sort_by(|&a, &b| {
        hunks[a]
            .index
            .cmp(&hunks[b].index)
            .then(hunks[a].del.cmp(&hunks[b].del))
    });
    let draft: String = ordered
        .iter()
        .map(|&hi| hunks[hi].insert.as_str())
        .collect();
    RebaseCore {
        rebased: Rebased {
            placed,
            clashes,
            draft,
            unreplayed_deletes,
        },
        placed_from,
    }
}

/// Carry `hunks` (made against `base`, ordered, non-overlapping) onto `theirs`,
/// one remote region at a time. Each hunk shifts past earlier regions and lands
/// where the two texts agree around it. A hunk overlapping a region cannot be
/// placed without guessing: clashing hunks merge (with the regions they touch)
/// into `clashes` instead. Pending text is never silently dropped.
#[allow(dead_code)]
fn rebase_hunks(hunks: &[Hunk], base: &str, theirs: &str) -> Rebased {
    rebase_core(hunks, &chars_of(base), &chars_of(theirs)).rebased
}

/// Apply hunks (in `text`'s coordinates, ordered) to `text`.
#[allow(dead_code)]
fn apply_hunks(text: &str, hunks: &[Hunk]) -> String {
    apply_hunks_chars(&chars_of(text), hunks)
}

fn apply_hunks_chars(text: &[char], hunks: &[Hunk]) -> String {
    let mut sorted: Vec<&Hunk> = hunks.iter().collect();
    sorted.sort_by(|a, b| a.index.cmp(&b.index).then(a.del.cmp(&b.del)));
    let mut out = String::new();
    let mut pos = 0;
    for h in sorted {
        out.push_str(&slice(text, pos, h.index));
        out.push_str(&h.insert);
        pos = h.index + h.del;
    }
    out.push_str(&slice(text, pos, text.len()));
    out
}

/// Why [`merge_hunks`] refused its input hunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidHunks {
    /// Not in ascending order, or two hunks overlap or touch (`prev.index +
    /// prev.del >= next.index`). Adjacent edits must arrive as one coalesced
    /// hunk, as [`hunks_between`] and the kit's `pendingIntent` produce them.
    NotSeparated,
    /// A hunk reaches past the end of `base`.
    OutOfRange,
}

impl InvalidHunks {
    /// Stable code recorded in the shared vectors.
    pub fn code(self) -> &'static str {
        match self {
            InvalidHunks::NotSeparated => "hunks_not_separated",
            InvalidHunks::OutOfRange => "hunks_out_of_range",
        }
    }
}

/// Hunks must be ordered, strictly separated and inside the base.
fn validate_hunks(hunks: &[Hunk], base_len: usize) -> Result<(), InvalidHunks> {
    let mut prev_end: Option<usize> = None;
    for h in hunks {
        if prev_end.is_some_and(|end| end >= h.index) {
            return Err(InvalidHunks::NotSeparated);
        }
        let end = h.index.checked_add(h.del).ok_or(InvalidHunks::OutOfRange)?;
        if end > base_len {
            return Err(InvalidHunks::OutOfRange);
        }
        prev_end = Some(end);
    }
    Ok(())
}

/// Three-way merge from explicit hunks: [`rebase_hunks`] plus applying the
/// placed hunks to `theirs`, and locating each clash in the merged text.
///
/// The hunks must be ordered, strictly separated (no two overlapping or
/// touching) and inside `base`; otherwise this returns [`InvalidHunks`].
/// [`rebase_hunks`] accepts any hunks, with the kit's exact semantics, but a
/// clash passage can only be located in the merged text when no placed hunk
/// lands inside it, which separation guarantees: touching replacements that
/// clash would group into one passage while a hunk between them places inside it.
pub fn merge_hunks(hunks: &[Hunk], base: &str, theirs: &str) -> Result<BodyMerge, InvalidHunks> {
    let base = chars_of(base);
    validate_hunks(hunks, base.len())?;
    Ok(merge_validated(hunks, &base, &chars_of(theirs)))
}

/// Where placed hunks land relative to a clash passage. Placed hunks never
/// overlap a region, and with separated hunks every clash span is a union of
/// regions and the hunks that touched them, so each placed hunk is wholly
/// before or after a span (a hunk touching the start edge lands before the
/// passage; one at the end edge lands after it). Source hunks are ordered, so
/// "before a clash" is a prefix of the placed list: prefix sums of the length
/// changes, found by binary search.
struct PlacedShifts {
    /// End (in base) of each placed hunk's source hunk, ascending.
    source_end: Vec<usize>,
    /// `cum[i]` = total length change of `placed[..i]`.
    cum: Vec<isize>,
}

impl PlacedShifts {
    fn new(hunks: &[Hunk], core: &RebaseCore) -> Self {
        let source_end = core
            .placed_from
            .iter()
            .map(|&src| hunks[src].index + hunks[src].del)
            .collect();
        let mut cum = Vec::with_capacity(core.rebased.placed.len() + 1);
        let mut running = 0isize;
        cum.push(running);
        for p in &core.rebased.placed {
            let inserted = p.insert.chars().count();
            count_work_n(1 + inserted);
            running += inserted as isize - p.del as isize;
            cum.push(running);
        }
        PlacedShifts { source_end, cum }
    }

    /// Total length change of the placed hunks that end at or before `base_start`.
    fn before(&self, base_start: usize) -> isize {
        self.cum[self.source_end.partition_point(|&end| {
            count_work();
            end <= base_start
        })]
    }
}

fn merge_validated(hunks: &[Hunk], base: &[char], theirs: &[char]) -> BodyMerge {
    let core = rebase_core(hunks, base, theirs);
    let merged = apply_hunks_chars(theirs, &core.rebased.placed);
    let shifts = PlacedShifts::new(hunks, &core);
    let clashes = core
        .rebased
        .clashes
        .into_iter()
        .map(|clash| {
            let before = shifts.before(clash.base_start);
            let at_start = offset(clash.theirs_start, before);
            let at_end = at_start + (clash.theirs_end - clash.theirs_start);
            MergedClash {
                clash,
                at_start,
                at_end,
            }
        })
        .collect();
    BodyMerge {
        merged,
        placed: core.rebased.placed,
        clashes,
    }
}

/// String-level three-way merge: derive the person's hunks by diffing
/// `base`→`mine` ([`hunks_between`]), then [`merge_hunks`] onto `theirs`.
pub fn merge_bodies(base: &str, mine: &str, theirs: &str) -> BodyMerge {
    let (base, mine, theirs) = (chars_of(base), chars_of(mine), chars_of(theirs));
    let hunks = hunks_between_chars(&base, &mine);
    // Derived hunks are separated by construction: regions are split by at
    // least one equal token, so no validation is needed.
    debug_assert!(validate_hunks(&hunks, base.len()).is_ok());
    merge_validated(&hunks, &base, &theirs)
}

#[cfg(test)]
mod tests {
    //! Runs every shared vector in `protocol/vectors/body-merge/` against the
    //! port. The vitest runner (`web/apps/test/coedit/bodyMerge.vectors.test.ts`)
    //! runs the same files against the kit's TypeScript; the files are produced
    //! by the TS (`generateBodyMergeVectors.ts`), so the two implementations are
    //! held to identical results.
    use super::*;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    const FILES: &[(&str, &str)] = &[
        (
            "rebase-hunks.json",
            include_str!("../../../protocol/vectors/body-merge/rebase-hunks.json"),
        ),
        (
            "property-seeded.json",
            include_str!("../../../protocol/vectors/body-merge/property-seeded.json"),
        ),
        (
            "caps.json",
            include_str!("../../../protocol/vectors/body-merge/caps.json"),
        ),
        (
            "merge-bodies.json",
            include_str!("../../../protocol/vectors/body-merge/merge-bodies.json"),
        ),
    ];

    /// Strings longer than this many scalars appear in `expect` as a digest.
    const DIGEST_ABOVE: usize = 256;

    /// A string, or `{repeat, times}` / `{concat: [..]}` over recipes.
    fn expand(recipe: &Value) -> String {
        match recipe {
            Value::String(s) => s.clone(),
            Value::Object(o) if o.contains_key("repeat") => {
                expand(&o["repeat"]).repeat(o["times"].as_u64().expect("times") as usize)
            }
            Value::Object(o) if o.contains_key("concat") => o["concat"]
                .as_array()
                .expect("concat")
                .iter()
                .map(expand)
                .collect(),
            other => panic!("bad recipe {other}"),
        }
    }

    /// Long strings become `{len, sha256}` (scalar length, SHA-256 of the UTF-8
    /// bytes), the same rule the TS generator applies.
    fn text(s: &str) -> Value {
        let len = s.chars().count();
        if len > DIGEST_ABOVE {
            let digest = Sha256::digest(s.as_bytes());
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            json!({ "len": len, "sha256": hex })
        } else {
            Value::String(s.to_string())
        }
    }

    fn hunk_json(h: &Hunk) -> Value {
        json!({ "index": h.index, "del": h.del, "insert": text(&h.insert) })
    }

    fn hunk_from(v: &Value) -> Hunk {
        Hunk {
            index: v["index"].as_u64().expect("index") as usize,
            del: v["del"].as_u64().expect("del") as usize,
            insert: v["insert"].as_str().expect("insert").to_string(),
        }
    }

    fn clash_json(c: &MergedClash) -> Value {
        let k = &c.clash;
        json!({
            "base_start": k.base_start, "base_end": k.base_end,
            "base": text(&k.base), "mine": text(&k.mine), "theirs": text(&k.theirs),
            "theirs_start": k.theirs_start, "theirs_end": k.theirs_end,
        })
    }

    fn sub(chars: &[char], from: usize, to: usize) -> String {
        chars[from..to].iter().collect()
    }

    fn run_case(file: &str, case: &Value) {
        let name = case["name"].as_str().expect("name");
        let ctx = format!("{file}: {name}");
        let base = expand(&case["base"]);
        let mine = expand(&case["mine"]);
        let theirs = expand(&case["theirs"]);
        let given: Option<Vec<Hunk>> = case.get("hunks").map(|hs| {
            hs.as_array()
                .expect("hunks")
                .iter()
                .map(hunk_from)
                .collect()
        });

        // Pieces that mirror the TS surface: regions, hunks, rebase, merge.
        let regions: Vec<Value> = diff_regions(&base, &theirs)
            .iter()
            .map(|r| {
                json!({ "base_start": r.base_start, "base_end": r.base_end,
                        "theirs_start": r.theirs_start, "theirs_end": r.theirs_end })
            })
            .collect();
        let hunks = given.clone().unwrap_or_else(|| hunks_between(&base, &mine));
        let rebased = rebase_hunks(&hunks, &base, &theirs);
        let rebase_fields = |actual: &mut serde_json::Map<String, Value>| {
            actual.insert("regions".into(), Value::Array(regions.clone()));
            actual.insert(
                "placed".into(),
                Value::Array(rebased.placed.iter().map(hunk_json).collect()),
            );
            actual.insert(
                "clashes".into(),
                Value::Array(
                    rebased
                        .clashes
                        .iter()
                        .map(|k| {
                            clash_json(&MergedClash {
                                clash: k.clone(),
                                at_start: 0,
                                at_end: 0,
                            })
                        })
                        .collect(),
                ),
            );
            actual.insert("draft".into(), text(&rebased.draft));
            actual.insert(
                "unreplayed_deletes".into(),
                json!(rebased.unreplayed_deletes),
            );
        };

        // Explicit hunks merge_hunks refuses: rebase_hunks still has its exact
        // kit semantics, merge_hunks returns the recorded code.
        if let Some(code) = case["expect"].get("rejected") {
            assert!(given.is_some(), "{ctx}: only explicit hunks can be refused");
            let err = merge_hunks(&hunks, &base, &theirs).expect_err(&ctx);
            let mut actual = serde_json::Map::new();
            actual.insert("rejected".into(), json!(err.code()));
            rebase_fields(&mut actual);
            assert_eq!(Value::Object(actual), case["expect"], "{ctx}");
            assert_eq!(code, err.code(), "{ctx}");
            return;
        }

        let merge = merge_hunks(&hunks, &base, &theirs).unwrap_or_else(|e| panic!("{ctx}: {e:?}"));
        if given.is_none() {
            // The string-level entry point is exactly the derived pipeline.
            assert_eq!(merge_bodies(&base, &mine, &theirs), merge, "{ctx}");
        }
        assert_eq!(rebased.placed, merge.placed, "{ctx}");
        assert_eq!(
            rebased.clashes,
            merge
                .clashes
                .iter()
                .map(|c| c.clash.clone())
                .collect::<Vec<_>>(),
            "{ctx}"
        );

        let mut actual = serde_json::Map::new();
        if case.get("summary").is_some() {
            // Counts and digests only (the full result would be megabytes).
            actual.insert("regions".into(), json!(regions.len()));
            actual.insert("hunks".into(), json!(hunks.len()));
            actual.insert("placed".into(), json!(merge.placed.len()));
            actual.insert("clashes".into(), json!(merge.clashes.len()));
            actual.insert("draft".into(), text(&rebased.draft));
            actual.insert(
                "unreplayed_deletes".into(),
                json!(rebased.unreplayed_deletes),
            );
            actual.insert("merged".into(), text(&merge.merged));
            assert_eq!(Value::Object(actual), case["expect"], "{ctx}");
            return;
        }
        if given.is_none() {
            actual.insert(
                "hunks".into(),
                Value::Array(hunks.iter().map(hunk_json).collect()),
            );
        }
        rebase_fields(&mut actual);
        actual.insert(
            "clashes".into(),
            Value::Array(merge.clashes.iter().map(clash_json).collect()),
        );
        actual.insert("merged".into(), text(&merge.merged));
        actual.insert(
            "at".into(),
            Value::Array(
                merge
                    .clashes
                    .iter()
                    .map(|c| json!({ "at_start": c.at_start, "at_end": c.at_end }))
                    .collect(),
            ),
        );
        assert_eq!(Value::Object(actual), case["expect"], "{ctx}");

        // Invariants that hold for every vector, whatever the file says.
        let (b, t, m): (Vec<char>, Vec<char>, Vec<char>) =
            (chars_of(&base), chars_of(&theirs), chars_of(&merge.merged));
        for c in &merge.clashes {
            let k = &c.clash;
            assert_eq!(
                sub(&b, k.base_start, k.base_end),
                k.base,
                "{ctx}: base slice"
            );
            assert_eq!(
                sub(&t, k.theirs_start, k.theirs_end),
                k.theirs,
                "{ctx}: theirs slice"
            );
            assert_eq!(
                sub(&m, c.at_start, c.at_end),
                k.theirs,
                "{ctx}: merged[at_start..at_end] == theirs"
            );
        }
        for pair in merge.placed.windows(2) {
            assert!(
                pair[0].index + pair[0].del <= pair[1].index,
                "{ctx}: placed hunks overlap"
            );
        }
    }

    #[test]
    fn shared_vectors_pass() {
        let mut total = 0;
        for (file, raw) in FILES {
            let doc: Value = serde_json::from_str(raw).unwrap_or_else(|e| panic!("{file}: {e}"));
            assert_eq!(doc["format"], "body-merge-vectors/1", "{file}");
            assert_eq!(doc["unit"], "unicode_scalars", "{file}");
            for case in doc["cases"].as_array().expect("cases") {
                run_case(file, case);
                total += 1;
            }
        }
        assert!(total >= 300, "only {total} vectors ran");
    }

    #[test]
    fn every_vector_file_is_run() {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/vectors/body-merge"
        );
        let mut on_disk: Vec<String> = std::fs::read_dir(dir)
            .expect("vector directory")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".json"))
            .collect();
        on_disk.sort();
        let mut listed: Vec<String> = FILES.iter().map(|(n, _)| n.to_string()).collect();
        listed.sort();
        assert_eq!(on_disk, listed, "add the new file to FILES");
    }

    #[test]
    fn required_vector_categories_are_present() {
        let mut names = Vec::new();
        for (_, raw) in FILES {
            let doc: Value = serde_json::from_str(raw).expect("json");
            for case in doc["cases"].as_array().expect("cases") {
                names.push(case["category"].as_str().expect("category").to_string());
            }
        }
        for required in [
            "kit-placement",
            "kit-adjacency",
            "kit-unicode",
            "parity",
            "property-disjoint-overlapping",
            "property-repeated-lines",
            "cap-line",
            "cap-char",
            "cap-char-scope",
            "s8.3a-deletion",
            "ambiguity-pair",
            "must-not-extend",
            "lineage",
            "merge-bodies",
        ] {
            assert!(
                names.iter().any(|n| n == required),
                "no vector in category {required}"
            );
        }
    }

    #[test]
    fn scalar_offsets_are_not_bytes_or_utf16() {
        // 😀 is 4 bytes and 2 UTF-16 units but one scalar.
        let merge = merge_bodies("😀ab", "😀aXb", "😀ab");
        assert_eq!(merge.merged, "😀aXb");
        assert_eq!(
            merge.placed,
            vec![Hunk {
                index: 2,
                del: 0,
                insert: "X".into()
            }]
        );
    }

    #[test]
    fn merge_hunks_refuses_unseparated_or_out_of_range_hunks() {
        let h = |index, del, insert: &str| Hunk {
            index,
            del,
            insert: insert.into(),
        };
        // The review example: touching hunks around a clash would place "!"
        // inside the clash passage.
        let touching = [h(0, 1, "A"), h(1, 0, "!"), h(1, 2, "B")];
        assert_eq!(
            merge_hunks(&touching, "abc", "XbZ"),
            Err(InvalidHunks::NotSeparated)
        );
        // rebase_hunks keeps the kit's semantics for the same input.
        let r = rebase_hunks(&touching, "abc", "XbZ");
        assert_eq!(r.placed, vec![h(1, 0, "!")]);
        assert_eq!(r.clashes.len(), 1);
        assert_eq!(
            merge_hunks(&[h(2, 1, "x"), h(0, 1, "y")], "abc", "abc"),
            Err(InvalidHunks::NotSeparated)
        );
        assert_eq!(
            merge_hunks(&[h(2, 5, "")], "abc", "abc"),
            Err(InvalidHunks::OutOfRange)
        );
        assert!(merge_hunks(&[h(0, 1, "A"), h(2, 1, "C")], "abc", "abc").is_ok());
        assert!(merge_hunks(&[], "abc", "abc").is_ok());
    }

    fn work_since_reset() -> usize {
        REGION_WORK.with(|w| w.get())
    }

    /// Near-linear in hunks + regions: a few dozen probes per item. The old
    /// scan-from-the-start behaviours were about hunks x regions / 2.
    fn assert_near_linear(work: usize, hunks: usize, regions: usize, label: &str) {
        let bound = 64 * (hunks + regions);
        eprintln!("{label}: work {work}, bound {bound} ({hunks} hunks, {regions} regions)");
        assert!(
            work <= bound,
            "{label}: {work} units of work for {hunks} hunks and {regions} regions (bound {bound})"
        );
    }

    #[test]
    fn many_hunks_and_regions_within_the_caps_do_near_linear_work() {
        // 20000 hunks against 20000 regions, all within the caps; every hunk
        // touches a remote region at an edge, so all place.
        let block = |pair: &str| format!("{}\nkeep\n", pair.repeat(100));
        let base = block("ab").repeat(200);
        let mine = block("Ab").repeat(200);
        let theirs = block("aB").repeat(200);
        REGION_WORK.with(|w| w.set(0));
        let merge = merge_bodies(&base, &mine, &theirs);
        let work = work_since_reset();
        assert_eq!(merge.placed.len(), 20_000);
        assert!(merge.clashes.is_empty());
        assert_eq!(merge.merged, block("AB").repeat(200));
        assert_near_linear(work, 20_000, 20_000, "all place");
        let rebased = rebase_hunks(&hunks_between(&base, &mine), &base, &theirs);
        assert_eq!(rebased.placed, merge.placed);
    }

    #[test]
    fn many_placed_hunks_and_many_separate_clashes_do_near_linear_work() {
        // 50 lines of 100 units "pqr ", each followed by an equal line (so every
        // changed line is its own block under the character caps). theirs changes every r to R (5000
        // regions). mine changes every p to P (5000 hunks that place, clear of
        // the regions) and every r to X (5000 hunks that clash, each its own
        // passage). The clash-coordinate path must stay linear too.
        let line = |unit: &str| format!("{}\nkeep\n", unit.repeat(100));
        let base = line("pqr ").repeat(50);
        let mine = line("PqX ").repeat(50);
        let theirs = line("pqR ").repeat(50);
        REGION_WORK.with(|w| w.set(0));
        let merge = merge_bodies(&base, &mine, &theirs);
        let work = work_since_reset();

        assert_eq!(merge.merged, line("PqR ").repeat(50));
        assert_eq!(merge.placed.len(), 5_000);
        assert_eq!(merge.clashes.len(), 5_000);
        let merged: Vec<char> = merge.merged.chars().collect();
        for (n, c) in merge.clashes.iter().enumerate() {
            let (row, unit) = (n / 100, n % 100);
            let pos = row * 406 + unit * 4 + 2; // the r of this unit
            assert_eq!(
                (
                    c.clash.base.as_str(),
                    c.clash.mine.as_str(),
                    c.clash.theirs.as_str()
                ),
                ("r", "X", "R")
            );
            assert_eq!((c.clash.base_start, c.clash.base_end), (pos, pos + 1));
            assert_eq!((c.clash.theirs_start, c.clash.theirs_end), (pos, pos + 1));
            // Every P lands before its clash and is the same width as the p it replaced.
            assert_eq!((c.at_start, c.at_end), (pos, pos + 1));
            assert_eq!(merged[c.at_start], 'R');
        }
        assert_near_linear(work, 10_000, 5_000, "placed + clashes");
        let rebased = rebase_hunks(&hunks_between(&base, &mine), &base, &theirs);
        assert_eq!(rebased.placed, merge.placed);
        assert_eq!(
            rebased.clashes,
            merge
                .clashes
                .iter()
                .map(|c| c.clash.clone())
                .collect::<Vec<_>>()
        );
    }
}
