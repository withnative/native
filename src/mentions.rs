//! Lexical record mentions in record bodies (slice 1: scanner only).
//!
//! [`scan_body`] finds the textual shapes that *may* address a record without
//! deciding whether they do. Resolution — prefix scans, visibility, ambiguity —
//! belongs to later slices and to `mcp::record_ref`; this module never touches
//! the database, so its output is stable for a given input byte string.
//!
//! ## Forms (grammar v1)
//!
//! Grammar v1 is the demo `refs.js` behaviour accepted by plan a9392df —
//! deliberately not CommonMark:
//!
//! - `url` — a Native address on `n8v.to` or `app.withnative.ai` with an
//!   optional `http://` / `https://` scheme (`https://n8v.to/abc1234`,
//!   `n8v.to/abc1234`). The first path segment follows the demo grammar
//!   `[A-Za-z0-9_-]{4,64}`; a full UUID in that segment
//!   (`n8v.to/0189d4c6-1f2a-4a1b-9c3d-5e6f70819293`) is still lexical
//!   parsing: recognising the shape commits to nothing about whether the id
//!   exists or who may see it.
//! - `wiki_hex` — a `[[reference]]` whose trimmed reference is hex-shaped.
//! - `wiki_name` — the same bracket shape with a non-hex, name-shaped
//!   reference (`[[My Note]]`, `[[ My Note ]]`).
//! - `bare_hex` — an exact seven-hex run in prose (`see abc1234`).
//!
//! There is no `|label` form: any `|` inside the brackets rejects the wiki
//! candidate outright.
//!
//! Every occurrence preserves the reference exactly as authored in
//! [`Occurrence::authored_reference`] and separately carries a lowercased
//! [`Occurrence::lookup_key`] for case-insensitive matching. Dashes are kept
//! verbatim in both: canonical folding (dash stripping, prefix windows) is the
//! resolution layer's job, mirroring `canonical_prefix` in `mcp::record_ref`.
//!
//! ## Design judgments (grammar v1)
//!
//! - **Bare means exactly seven.** The engine mints seven-hex display
//!   references and accepts six-hex input, but prose scanning is not input
//!   classification: a six-hex run in prose is far more likely to be a word
//!   fragment than an address, so only exact-seven runs match. Longer runs
//!   (eight, nine, …) match nothing — no substring of a longer run is an
//!   occurrence.
//! - **Bare boundaries mirror the demo lookarounds.** A bare candidate
//!   adjacent to an ASCII letter, digit or `-` is not an occurrence. This
//!   excludes UUID-internal segments (dash-adjacent) and word-internal hex
//!   without a separate UUID detector. Underscore adjacency is allowed:
//!   `_abc1234_` matches.
//! - **URL segments follow the demo path grammar**, not the hex window: the
//!   first segment is `[A-Za-z0-9_-]{4,64}`, preserved exactly as authored
//!   with a lowercase lookup key. A scheme-less `n8v.to/<ref>` matches like
//!   the scheme-ful form; a `www.` prefix is not special and a
//!   non-`/` character after the host is not a URL. Free-prose UUIDs remain
//!   excluded — only a Native host prefix makes a UUID-shaped path lexical.
//! - **Wiki content is trimmed, plain and bounded.** The authored reference
//!   is the inner text with leading/trailing whitespace trimmed; a
//!   trimmed-empty reference is rejected. Any `|`, `[`, `]` or newline in
//!   the raw inner text rejects the candidate, as does a trimmed reference
//!   over 80 characters (padding does not buy extra room, nor does it cost
//!   any: an 80-after-trim reference is accepted however padded). A
//!   rejected-but-closed `[[…]]` span is consumed without emitting (bracket
//!   atomicity): the inner text is wiki territory, so a rejected
//!   `[[ABC1234|Alias]]` never leaks a `bare_hex`. An unclosed `[[`
//!   consumes nothing.
//! - **Wiki search is bounded.** The closing `]]` is searched within a 512
//!   byte window, so long unmatched `[[` input scans in O(n), not O(n²).
//! - **Fences follow the demo `fencedLines` rule mechanically**, not
//!   CommonMark: a line with up to three leading spaces/tabs followed by a
//!   run of 3+ backticks or tildes opens (any trailing info text allowed,
//!   backticks included); any later line with up to three leading
//!   spaces/tabs followed by a 3+ run of the *same* character closes,
//!   regardless of opener length or trailing text. A mismatched character
//!   never closes, and an unclosed opener swallows to end of input. Inline
//!   code spans are *not* skipped.
//! - **Spans are UTF-8 byte offsets on character boundaries**, named
//!   `span_start`/`span_end` (the vocabulary slice 2 stamps into rows).
//!   Non-ASCII text before a mention shifts its offsets by bytes, never by
//!   chars; only ASCII bytes participate in matching, so boundaries hold by
//!   construction. JS consumers must convert bytes to UTF-16 indices.
//! - **URL spans cover the whole URL** through any query/fragment, trailing
//!   `.,;:!?)]}'"` trimmed; `authored_reference` is only the first path
//!   segment. The trim set is retained from slice 1: it can shave a
//!   meaningful trailing character off exotic URLs, but matches the demo
//!   behaviour the corpus pins.
//!
//! ## Deliberate low-risk divergences from the demo (behaviour unchanged)
//!
//! - **Fence indentation is ASCII space/tab**, not full JS `\s`: exotic
//!   whitespace (form feeds, Unicode spaces) neither indents a fence line
//!   nor breaks one.
//! - **Scheme-less hosts carry a boundary guard**: a preceding ASCII letter,
//!   digit, `.`, `_`, `-` or `/` rejects the match, so `xn8v.to/…` prose
//!   never scans as a URL.
//! - **Over-long path segments are rejected, not truncated**: a 65-character
//!   segment yields no URL rather than a 64-character one.
//! - **Wiki length counts Unicode scalar values**, not JS UTF-16 code units:
//!   an astral character is 1 of the 80 here, 2 there.
//!
//! [`Occurrence`] is intentionally free of serde: the shared JSON fixture
//! corpus under `tests/fixtures/mentions/` is read with `serde_json::Value`
//! on the test side so this module keeps zero dependencies.
//!
//! Slice 5 (demo lineage) will add the JS consumer over the same corpus;
//! nothing here assumes a renderer.

/// Parser version stamped alongside derived mention rows by later slices.
///
/// Bump only when [`scan_body`]'s output changes for some input, so stored
/// rows can tell whether they were derived by this scanner.
pub const MENTION_PARSER_VERSION: i64 = 1;

/// The lexical shape of one mention occurrence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MentionForm {
    /// A Native address on `n8v.to` / `app.withnative.ai`, scheme optional.
    Url,
    /// `[[hex]]` (surrounding whitespace trimmed before classification).
    WikiHex,
    /// `[[name]]` (surrounding whitespace trimmed before classification).
    WikiName,
    /// An exact seven-hex run in prose.
    BareHex,
}

impl MentionForm {
    /// Fixture- and row-stable snake_case name (`url`, `wiki_hex`,
    /// `wiki_name`, `bare_hex`).
    pub fn as_str(self) -> &'static str {
        match self {
            MentionForm::Url => "url",
            MentionForm::WikiHex => "wiki_hex",
            MentionForm::WikiName => "wiki_name",
            MentionForm::BareHex => "bare_hex",
        }
    }
}

/// One lexical mention occurrence in a body.
///
/// `span_start`/`span_end` are byte offsets into the scanned `&str`, always on
/// character boundaries; `span_end` is exclusive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Occurrence {
    /// Which lexical shape matched.
    pub form: MentionForm,
    /// The reference exactly as authored (URL first path segment, trimmed
    /// wiki reference, or the bare run).
    pub authored_reference: String,
    /// `authored_reference` lowercased for case-insensitive matching.
    pub lookup_key: String,
    /// Byte offset of the first byte of the whole mention construct.
    pub span_start: usize,
    /// Byte offset one past the last byte of the whole mention construct.
    pub span_end: usize,
}

/// Scan `body` for lexical record mentions, left to right.
///
/// Fenced code blocks contribute no occurrences. Matches never overlap:
/// at each position a URL is tried first, then a wiki reference, then a
/// bare run, and a match consumes its span.
pub fn scan_body(body: &str) -> Vec<Occurrence> {
    let bytes = body.as_bytes();
    let fences = fenced_ranges(body);
    let mut fence_idx = 0usize;
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if fence_idx < fences.len() {
            let (start, end) = fences[fence_idx];
            if i >= end {
                fence_idx += 1;
                continue;
            }
            if i >= start {
                i = end;
                continue;
            }
        }
        if !body.is_char_boundary(i) {
            i += 1;
            continue;
        }
        if let Some((occurrence, next)) = match_url(bytes, i) {
            out.push(occurrence);
            i = next;
            continue;
        }
        match match_wiki(body, i) {
            WikiScan::Hit(occurrence, next) => {
                out.push(occurrence);
                i = next;
                continue;
            }
            WikiScan::Skip(next) => {
                i = next;
                continue;
            }
            WikiScan::Miss => {}
        }
        if let Some(occurrence) = match_bare(bytes, i) {
            i = occurrence.span_end;
            out.push(occurrence);
            continue;
        }
        i += body[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
    }
    out
}

/// Byte ranges of fenced code blocks: `(start, end)` with `end` exclusive.
///
/// Demo `fencedLines`, mechanically: a fence line carries up to three leading
/// spaces/tabs followed by a run of at least three backticks or three tildes.
/// Any trailing text is ignored and there is no backtick-info restriction. A
/// fence line opens when none is open; a later fence line with the *same*
/// character closes regardless of run length. A line with the other character
/// never closes. An unclosed opener excludes everything to end of input.
fn fenced_ranges(body: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut open: Option<(u8, usize)> = None;
    let mut offset = 0usize;
    for line in body.split_inclusive('\n') {
        let line_start = offset;
        offset += line.len();
        let trimmed = line.strip_suffix('\n').unwrap_or(line);
        let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
        let indent = trimmed
            .bytes()
            .take_while(|b| *b == b' ' || *b == b'\t')
            .count();
        if indent > 3 {
            continue;
        }
        let rest = &trimmed[indent.min(trimmed.len())..];
        let fence_byte = match rest.as_bytes().first() {
            Some(b'`') => b'`',
            Some(b'~') => b'~',
            _ => continue,
        };
        if rest.bytes().take_while(|b| *b == fence_byte).count() < 3 {
            continue;
        }
        match open {
            None => open = Some((fence_byte, line_start)),
            Some((open_byte, open_start)) => {
                if open_byte == fence_byte {
                    ranges.push((open_start, offset));
                    open = None;
                }
            }
        }
    }
    if let Some((_, open_start)) = open {
        ranges.push((open_start, body.len()));
    }
    ranges
}

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

/// Demo bare lookaround: ASCII letters, digits and `-` make a hex run part of
/// a larger token (or a UUID segment) rather than a standalone reference.
/// Underscores are not word bytes here — `_abc1234_` matches.
fn is_bare_adjacent(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

fn starts_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len()
        && haystack[..needle.len()]
            .iter()
            .zip(needle.iter())
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
}

/// Dash-stripped hex of length 6..=32, for lexical classification of a
/// trimmed wiki reference only. This is deliberately not `canonical_prefix`'s
/// resolvable prefix bound (which tops out below a full 32 hex digits):
/// classification says what shape the text is, resolution decides what it
/// addresses, so a 32-hex wiki reference classifies as `wiki_hex` here and
/// the resolution layer rules on resolvability.
fn is_reference_hex(reference: &str) -> bool {
    let stripped: String = reference.chars().filter(|c| *c != '-').collect();
    (6..=32).contains(&stripped.len()) && stripped.bytes().all(is_hex)
}

/// Try a Native address at byte offset `i`. Returns the occurrence and the
/// offset to resume scanning from (end of the URL span).
///
/// The scheme is optional (`n8v.to/<ref>` matches like `https://n8v.to/<ref>`);
/// there is no `www.` special form. The first path segment must match the demo
/// grammar `[A-Za-z0-9_-]{4,64}` — a full UUID in that slot is lexical shape,
/// not resolution. The span extends through the rest of the URL
/// (query/fragment included) with trailing prose punctuation trimmed.
fn match_url(bytes: &[u8], i: usize) -> Option<(Occurrence, usize)> {
    let mut j = i;
    let mut schemed = false;
    if starts_insensitive(&bytes[j..], b"https://") {
        j += 8;
        schemed = true;
    } else if starts_insensitive(&bytes[j..], b"http://") {
        j += 7;
        schemed = true;
    }
    if schemed {
        if i > 0 && bytes[i - 1].is_ascii_alphanumeric() {
            return None;
        }
    } else if i > 0 && is_schemeless_adjacent(bytes[i - 1]) {
        return None;
    }
    let tail = &bytes[j.min(bytes.len())..];
    let host_len = if starts_insensitive(tail, b"n8v.to") {
        6
    } else if starts_insensitive(tail, b"app.withnative.ai") {
        17
    } else {
        return None;
    };
    j += host_len;
    if bytes.get(j) != Some(&b'/') {
        return None;
    }
    j += 1;
    let ref_start = j;
    while j < bytes.len() && is_segment_byte(bytes[j]) {
        j += 1;
    }
    let len = j - ref_start;
    if !(4..=64).contains(&len) {
        return None;
    }
    let segment: String = bytes[ref_start..j].iter().map(|b| *b as char).collect();
    let mut end = j;
    while end < bytes.len() && is_url_byte(bytes[end]) {
        end += 1;
    }
    while end > j && is_trailing_punct(bytes[end - 1]) {
        end -= 1;
    }
    Some((
        Occurrence {
            form: MentionForm::Url,
            lookup_key: segment.to_ascii_lowercase(),
            authored_reference: segment,
            span_start: i,
            span_end: end,
        },
        end,
    ))
}

/// Bytes that would make a scheme-less host match start mid-token.
fn is_schemeless_adjacent(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/')
}

/// Demo first-segment grammar: ASCII letters, digits, `_` and `-`.
fn is_segment_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

/// URL span characters: anything non-whitespace except angle brackets,
/// double quotes and backticks (which never belong to a pasted link).
fn is_url_byte(byte: u8) -> bool {
    !byte.is_ascii_whitespace() && !matches!(byte, b'<' | b'>' | b'"' | b'`')
}

/// Trailing punctuation trimmed from a URL span (prose-adjacent, not address).
fn is_trailing_punct(byte: u8) -> bool {
    matches!(
        byte,
        b'.' | b',' | b';' | b':' | b'!' | b'?' | b')' | b']' | b'}' | b'\'' | b'"'
    )
}

/// Outcome of probing a `[[` at one offset.
enum WikiScan {
    /// A valid wiki reference: the occurrence and the offset to resume from.
    Hit(Occurrence, usize),
    /// A closed but invalid `[[…]]`: consumed without emitting (bracket
    /// atomicity — the inner text never leaks a `bare_hex`).
    Skip(usize),
    /// No wiki shape here (no opener, or no closer in range): advance one.
    Miss,
}

/// Search window (bytes) for a wiki closer. A valid wiki holds at most 80
/// characters plus brackets, so a bounded window keeps long unmatched `[[`
/// input O(n) instead of O(n²). The window end retreats to a character
/// boundary (at most 3 bytes), so multibyte content crossing the edge cannot
/// panic and the bound stays constant.
const MAX_WIKI_SEARCH: usize = 512;

/// Maximum accepted trimmed wiki reference, in Unicode scalar values (not
/// JS UTF-16 code units — an astral character counts 1 here, 2 there).
const MAX_WIKI_CONTENT: usize = 80;

/// Try a `[[reference]]` at byte offset `i`.
fn match_wiki(body: &str, i: usize) -> WikiScan {
    if !body[i..].starts_with("[[") {
        return WikiScan::Miss;
    }
    let inner_start = i + 2;
    let tail = &body[inner_start..];
    let mut window_end = tail.len().min(MAX_WIKI_SEARCH);
    while !tail.is_char_boundary(window_end) {
        window_end -= 1;
    }
    let window = &tail[..window_end];
    let Some(rel) = window.find("]]") else {
        return WikiScan::Miss;
    };
    let inner = &tail[..rel];
    let end = inner_start + rel + 2;
    if inner.is_empty() || inner.contains(['\n', '\r', '[', ']', '|']) {
        return WikiScan::Skip(end);
    }
    let reference = inner.trim();
    if reference.is_empty() || reference.chars().count() > MAX_WIKI_CONTENT {
        return WikiScan::Skip(end);
    }
    let form = if is_reference_hex(reference) {
        MentionForm::WikiHex
    } else {
        MentionForm::WikiName
    };
    WikiScan::Hit(
        Occurrence {
            form,
            lookup_key: reference.to_lowercase(),
            authored_reference: reference.to_string(),
            span_start: i,
            span_end: end,
        },
        end,
    )
}

/// Try an exact seven-hex prose run starting at byte offset `i`.
fn match_bare(bytes: &[u8], i: usize) -> Option<Occurrence> {
    if !is_hex(bytes[i]) {
        return None;
    }
    if i > 0 && is_bare_adjacent(bytes[i - 1]) {
        return None;
    }
    let mut j = i;
    while j < bytes.len() && is_hex(bytes[j]) {
        j += 1;
    }
    if j - i != 7 {
        return None;
    }
    if j < bytes.len() && is_bare_adjacent(bytes[j]) {
        return None;
    }
    let reference: String = bytes[i..j].iter().map(|b| *b as char).collect();
    Some(Occurrence {
        form: MentionForm::BareHex,
        lookup_key: reference.to_ascii_lowercase(),
        authored_reference: reference,
        span_start: i,
        span_end: j,
    })
}
