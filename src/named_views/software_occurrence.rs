//! Fixture-only deterministic software-occurrence attester (no writes).
//!
//! Implements a **subset** of the retained package reference
//! (`armc/observed_software.py`, `native.software-observations/0.1`) and
//! therefore uses its own version `native.software-fixture-attestation.v1`.
//! Parity for the claims below is proved by committed synthetic expected
//! outputs generated from the reference (see
//! `fixtures/software/generate_reference_expected.py`, which pins the
//! reference digest and records the flag mapping). See
//! `docs/named-views-software-occurrence-design.md`.
//!
//! Line splitting, node lexing, escape decoding, property tokens, indentation
//! warnings and codepoint offsets mirror the reference. The attester adds
//! caps, which only ever shorten what is parsed: a capped result is Partial
//! with a continuation, never a fabricated complete one.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const ATTESTATION_VERSION: &str = "native.software-fixture-attestation.v1";
pub(crate) const COVERAGE_SCHEMA: &str = "native.software-fixture-coverage.v1";
pub(crate) const CLOSED_REQUIREMENTS: [&str; 3] = ["flags", "options", "parents"];

#[derive(Clone, Copy)]
pub(crate) struct Caps {
    pub chunks: usize,
    pub bytes: usize,
    pub nodes: usize,
    pub label: usize,
    pub role: usize,
    pub selector: usize,
    pub bid: usize,
    pub excerpt: usize,
    /// Bound on each diagnostic list (warnings, unparsed lines).
    pub diagnostics: usize,
}
impl Default for Caps {
    fn default() -> Self {
        Self {
            chunks: 64,
            bytes: 512 * 1024,
            nodes: 4096,
            label: 1024,
            role: 64,
            selector: 256,
            bid: 256,
            excerpt: 512,
            diagnostics: 4096,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Scope {
    pub namespace: String,
    pub trajectory: String,
    pub state: u32,
    pub view: String,
    pub scope_selector: String,
}

#[derive(Clone, Debug)]
pub(crate) struct Declared {
    pub sha256: String,
    pub len: usize,
    pub chunks: usize,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Chunk {
    pub ordinal: u32,
    pub byte_start: usize,
    pub byte_end: usize,
    pub sha256: String,
}

#[derive(Clone, Debug)]
pub(crate) struct Request {
    pub scope: Scope,
    pub source_ref: String,
    pub source_complete: Option<bool>,
    pub tree: String,
    pub declared: Declared,
    pub chunks: Vec<Chunk>,
    pub binding_revision: String,
    pub requirements: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Integrity {
    Verified,
    Clipped,
    Unknown,
    Corrupt,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Structural {
    Complete,
    Partial,
    Failed,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Semantic {
    Established,
    Partial,
    NotAttempted,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Binding {
    Bound,
    Inferred,
    Unresolved,
    Ambiguous,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Occurrence {
    pub occurrence_kind: &'static str,
    pub raw_label: String,
    /// True when `raw_label` is a cap-shortened prefix of the source label.
    pub label_capped: bool,
    pub search_label: String,
    pub raw_role: String,
    pub bid: Option<String>,
    pub source_order: u32,
    pub depth: usize,
    pub selector: String,
    pub parent_selector: Option<String>,
    pub parent_inferred: bool,
    pub binding_status: Binding,
    pub selected: &'static str,
    pub disabled: &'static str,
    /// True when the decoded source label is empty or whitespace.
    pub blank: &'static str,
    pub line: u32,
    pub char_start: usize,
    pub char_end: usize,
    pub excerpt: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct ChoiceGroup {
    pub control_selector: String,
    pub binding_revision: String,
    pub membership_policy: &'static str,
    pub boundary_method: &'static str,
    pub ordering_basis: &'static str,
    pub binding_status: Binding,
    pub option_selectors: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Coverage {
    pub coverage_schema: &'static str,
    pub scope_digest: String,
    pub source_set_digest: String,
    pub extractor_version: &'static str,
    pub binding_revision: String,
    pub requirements_digest: String,
    pub source_integrity: Integrity,
    pub structural_coverage: Structural,
    pub semantic_coverage: Semantic,
    pub omissions: BTreeSet<String>,
    /// First unattested position: (chunk ordinal containing it, Unicode
    /// codepoint offset from the start of the tree).
    pub continuation: Option<(u32, usize)>,
    pub parsed_nodes: u32,
    pub chunk_count: u32,
    pub expected_item_count: u32,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Identity {
    pub scope_digest: String,
    pub source_set_digest: String,
    pub extractor_version: &'static str,
    pub binding_revision: String,
    pub requirements_digest: String,
}

/// A reference-style structural warning on one source line.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Warning {
    pub line: u32,
    pub issue: &'static str,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Attestation {
    pub schema: &'static str,
    pub view: String,
    pub source_ref: String,
    pub identity: Identity,
    pub occurrences: Vec<Occurrence>,
    pub groups: Vec<ChoiceGroup>,
    pub warnings: Vec<Warning>,
    pub unparsed_lines: Vec<u32>,
    pub coverage: Coverage,
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Collision-free length-prefixed encoding for identity material.
pub(crate) fn encode(parts: &[&str]) -> String {
    let mut out = String::new();
    for part in parts {
        out.push_str(&part.chars().count().to_string());
        out.push(':');
        out.push_str(part);
    }
    out
}

/// Python `str.isspace` (Unicode White_Space plus the C0 separators).
fn py_space(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}
fn py_strip(s: &str) -> &str {
    s.trim_matches(py_space)
}
fn py_lstrip(s: &str) -> &str {
    s.trim_start_matches(py_space)
}

/// Byte length of the first Python-`splitlines(keepends=True)` line of `s`.
fn line_len(s: &str) -> usize {
    for (i, c) in s.char_indices() {
        match c {
            '\r' => {
                return if s[i + 1..].starts_with('\n') {
                    i + 2
                } else {
                    i + 1
                }
            }
            '\n' | '\u{0b}' | '\u{0c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2028}'
            | '\u{2029}' => return i + c.len_utf8(),
            _ => {}
        }
    }
    s.len()
}

/// Largest complete-line boundary at or before `limit` (a safe char boundary).
fn complete_line_prefix(tree: &str, limit: usize) -> usize {
    let mut end = 0usize;
    while end < tree.len() {
        let next = end + line_len(&tree[end..]);
        if next > limit {
            break;
        }
        end = next;
    }
    end
}

/// Ordinal of the chunk containing byte `at` (the last chunk if `at` is the end).
fn chunk_containing(chunks: &[Chunk], at: usize) -> u32 {
    chunks
        .partition_point(|c| c.byte_end <= at)
        .min(chunks.len().saturating_sub(1)) as u32
}

struct Parsed {
    depth: usize,
    bid: Option<String>,
    role: String,
    label: String,
    selected: &'static str,
    disabled: &'static str,
    warnings: Vec<&'static str>,
}

/// Decode AX quoted-string escapes exactly like the reference: invalid or
/// unpaired escapes keep their source spelling and add a diagnostic; a valid
/// `😀` surrogate pair combines into one scalar.
fn decode_ax(raw: &str) -> (String, Vec<&'static str>) {
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::new();
    let mut errors = Vec::new();
    let mut i = 0usize;
    let is_hex = |s: &[char]| s.iter().all(|c| c.is_ascii_hexdigit());
    while i < chars.len() {
        if chars[i] != '\\' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        if i + 1 >= chars.len() {
            errors.push("trailing_escape");
            out.extend(&chars[i..]);
            break;
        }
        let simple = match chars[i + 1] {
            '\\' => Some('\\'),
            '\'' => Some('\''),
            '"' => Some('"'),
            'n' => Some('\n'),
            't' => Some('\t'),
            'r' => Some('\r'),
            'b' => Some('\u{8}'),
            'f' => Some('\u{c}'),
            '/' => Some('/'),
            _ => None,
        };
        if let Some(c) = simple {
            out.push(c);
            i += 2;
            continue;
        }
        let width = match chars[i + 1] {
            'u' => 4,
            'x' => 2,
            _ => 0,
        };
        let digits = &chars[i + 2..(i + 2 + width).min(chars.len())];
        if width > 0 && digits.len() == width && is_hex(digits) {
            let mut code = digits
                .iter()
                .fold(0u32, |acc, c| acc * 16 + c.to_digit(16).unwrap_or(0));
            let mut consumed = 2 + width;
            if (0xD800..=0xDBFF).contains(&code) {
                let next =
                    &chars[(i + consumed).min(chars.len())..(i + consumed + 6).min(chars.len())];
                let low_pair = next.len() == 6
                    && next[0] == '\\'
                    && next[1] == 'u'
                    && matches!(next[2], 'd' | 'D')
                    && matches!(next[3], 'c'..='f' | 'C'..='F')
                    && is_hex(&next[4..]);
                if low_pair {
                    let low = next[2..]
                        .iter()
                        .fold(0u32, |acc, c| acc * 16 + c.to_digit(16).unwrap_or(0));
                    code = 0x10000 + (code - 0xD800) * 0x400 + low - 0xDC00;
                    consumed += 6;
                } else {
                    errors.push("unpaired_surrogate");
                    out.extend(&chars[i..i + consumed]);
                    i += consumed;
                    continue;
                }
            } else if (0xDC00..=0xDFFF).contains(&code) {
                errors.push("unpaired_surrogate");
                out.extend(&chars[i..i + consumed]);
                i += consumed;
                continue;
            }
            out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
            i += consumed;
            continue;
        }
        errors.push("unsupported_escape");
        out.extend(&chars[i..i + 2]);
        i += 2;
    }
    (out, errors)
}

/// Raw quoted content and consumed byte length; a closing quote is required.
fn quoted(text: &str) -> Result<(&str, usize), &'static str> {
    let quote = text
        .chars()
        .next()
        .filter(|c| matches!(c, '\'' | '"'))
        .ok_or("expected_quote")?;
    let mut escaped = false;
    for (index, ch) in text.char_indices().skip(1) {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == quote {
            return Ok((&text[1..index], index + 1));
        }
    }
    Err("unterminated_quote")
}

/// Property value: `None` is a bare key (reference `True`).
type Props = BTreeMap<String, Option<String>>;

/// Reference `_tail`: optional quoted label, then comma-separated properties.
/// An unquoted word is a property (and so a diagnostic), never the label.
fn tail(rest: &str) -> (String, Props, Vec<&'static str>) {
    let mut rest = py_strip(rest);
    let mut label = String::new();
    let mut errors = Vec::new();
    if rest.starts_with(['\'', '"']) {
        let (raw, end) = match quoted(rest) {
            Ok(found) => found,
            Err(code) => return (String::new(), Props::new(), vec![code]),
        };
        if rest[end..]
            .chars()
            .next()
            .is_some_and(|c| !(py_space(c) || c == ','))
        {
            return (String::new(), Props::new(), vec!["unconsumed_label_suffix"]);
        }
        let after = py_strip(&rest[end..]);
        rest = py_strip(after.strip_prefix(',').unwrap_or(after));
        let (decoded, decode_errors) = decode_ax(raw);
        label = decoded;
        errors.extend(decode_errors);
    }
    let mut tokens: Vec<&str> = Vec::new();
    let mut start = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (index, ch) in rest.char_indices() {
        if escaped {
            escaped = false;
        } else if quote.is_some() && ch == '\\' {
            escaped = true;
        } else if matches!(ch, '\'' | '"') && (quote.is_none() || quote == Some(ch)) {
            quote = if quote.is_none() { Some(ch) } else { None };
        } else if ch == ',' && quote.is_none() {
            tokens.push(py_strip(&rest[start..index]));
            start = index + 1;
        }
    }
    if quote.is_some() {
        errors.push("unterminated_property_quote");
    }
    if !rest.is_empty() {
        tokens.push(py_strip(&rest[start..]));
    }
    let mut props = Props::new();
    for token in tokens {
        let key_end = token
            .char_indices()
            .find(|(i, c)| {
                !(c.is_ascii_alphabetic() || *c == '_' || (*i > 0 && c.is_ascii_digit()))
            })
            .map_or(token.len(), |(i, _)| i);
        let (key, tail) = token.split_at(key_end);
        let value = match tail.strip_prefix('=') {
            _ if key.is_empty() => None,
            Some(value) => Some(Some(value)),
            None if tail.is_empty() => Some(None),
            None => None,
        };
        let Some(value) = value else {
            errors.push("unrecognized_property_span");
            continue;
        };
        if props.contains_key(key) {
            errors.push("duplicate_property");
        }
        let stored = match value {
            None => None,
            Some(value) if value.starts_with(['\'', '"']) => match quoted(value) {
                Ok((raw, used)) if used == value.len() => {
                    let (decoded, decode_errors) = decode_ax(raw);
                    errors.extend(decode_errors);
                    Some(decoded)
                }
                Ok(_) => {
                    errors.push("unconsumed_property_suffix");
                    Some(value.to_owned())
                }
                Err(code) => {
                    errors.push(code);
                    Some(value.to_owned())
                }
            },
            Some(value) if value.is_empty() || value.contains(['\'', '"']) => {
                errors.push("malformed_property_value");
                Some(value.to_owned())
            }
            Some(value) => Some(value.to_owned()),
        };
        props.insert(key.to_owned(), stored);
    }
    (label, props, errors)
}

/// Fixture flag mapping: bare key or `True` is true, `False` is false,
/// anything else (absent, other spellings) is unknown.
fn flag(props: &Props, name: &str) -> &'static str {
    match props.get(name) {
        Some(None) => "true",
        Some(Some(value)) if value == "True" => "true",
        Some(Some(value)) if value == "False" => "false",
        _ => "unknown",
    }
}

/// Reference `NODE_RE.fullmatch`:
/// `^(\t*)(?:\[(\w+)\]\s+)?([A-Za-z][A-Za-z0-9_]*)(?:(?:\s+|,\s*)(.*))?$`.
/// `None` means the line is not a node (the reference lists it as unparsed).
fn parse_line(line: &str) -> Option<Parsed> {
    let depth = line.bytes().take_while(|b| *b == b'\t').count();
    let mut rest = &line[depth..];
    let mut bid = None;
    if let Some(inner) = rest.strip_prefix('[') {
        let word_end = inner
            .char_indices()
            .find(|(_, c)| !(c.is_alphanumeric() || *c == '_'))
            .map_or(inner.len(), |(i, _)| i);
        let after = &inner[word_end..];
        if word_end > 0 && after.starts_with(']') && after[1..].chars().next().is_some_and(py_space)
        {
            bid = Some(inner[..word_end].to_owned());
            rest = py_lstrip(&after[1..]);
        }
    }
    if !rest.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let role_end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    let role = rest[..role_end].to_owned();
    let after = &rest[role_end..];
    let tail_text = match after.chars().next() {
        None => "",
        Some(c) if py_space(c) => py_lstrip(after),
        Some(',') => py_lstrip(&after[1..]),
        Some(_) => return None,
    };
    let (label, props, warnings) = tail(tail_text);
    Some(Parsed {
        depth,
        bid,
        role,
        label,
        selected: flag(&props, "selected"),
        disabled: flag(&props, "disabled"),
        warnings,
    })
}

fn is_truncation_marker(text: &str) -> bool {
    let trimmed = py_lstrip(text);
    if trimmed.starts_with("...") || trimmed.starts_with('…') {
        return true;
    }
    let head: String = trimmed
        .chars()
        .take(10)
        .flat_map(char::to_lowercase)
        .collect();
    head.starts_with("[truncated")
        || head.starts_with("<truncated")
        || head.starts_with("truncated")
}

fn search_label(raw: &str) -> String {
    raw.trim()
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_control_role(role: &str) -> bool {
    matches!(role, "combobox" | "listbox")
}

/// Pure deterministic attestation of one captured scope. No writes, no ids.
pub(crate) fn attest(request: &Request, caps: Caps) -> Attestation {
    let scope_digest = digest(
        encode(&[
            &request.scope.namespace,
            &request.scope.trajectory,
            &request.scope.state.to_string(),
            &request.scope.view,
            &request.scope.scope_selector,
        ])
        .as_bytes(),
    );
    let requirements: Vec<&str> = request.requirements.iter().map(String::as_str).collect();
    let requirements_digest = digest(encode(&requirements).as_bytes());
    let mut omissions = BTreeSet::new();
    let mut integrity = Integrity::Verified;
    let mut failed = false;

    if !is_sha256(&request.declared.sha256) {
        omissions.insert("declared_digest_invalid".to_owned());
        failed = true;
    }
    if request.declared.len != request.tree.len() {
        omissions.insert("declared_length_mismatch".to_owned());
        failed = true;
    }
    if request.declared.chunks != request.chunks.len() {
        omissions.insert("declared_chunk_count_mismatch".to_owned());
        failed = true;
    }
    let tree_digest = digest(request.tree.as_bytes());
    if tree_digest != request.declared.sha256 {
        omissions.insert("declared_digest_mismatch".to_owned());
        failed = true;
    }
    if request.chunks.is_empty() || request.tree.is_empty() {
        omissions.insert("no_attested_chunks".to_owned());
        if !failed {
            integrity = Integrity::Clipped;
        }
    }
    // The source set always commits to the declared digest, length and chunk
    // count (and the digest of the bytes actually supplied) plus every chunk as
    // supplied, so a failed or empty manifest cannot collide with another tree.
    let mut source_set = encode(&[
        &request.declared.sha256,
        &request.declared.len.to_string(),
        &request.declared.chunks.to_string(),
        &tree_digest,
        &request.tree.len().to_string(),
    ]);
    let mut expected_start = 0usize;
    for (index, chunk) in request.chunks.iter().enumerate() {
        source_set.push_str(&encode(&[
            &chunk.ordinal.to_string(),
            &chunk.byte_start.to_string(),
            &chunk.byte_end.to_string(),
            &chunk.sha256,
        ]));
        if !is_sha256(&chunk.sha256) {
            omissions.insert("chunk_digest_invalid".to_owned());
            failed = true;
        }
        if chunk.ordinal as usize != index || chunk.byte_start != expected_start {
            omissions.insert("chunk_order".to_owned());
            failed = true;
        }
        if chunk.byte_end > request.tree.len() || chunk.byte_start > chunk.byte_end {
            omissions.insert("chunk_missing".to_owned());
            if !failed {
                integrity = Integrity::Clipped;
            }
            continue;
        }
        if digest(&request.tree.as_bytes()[chunk.byte_start..chunk.byte_end]) != chunk.sha256 {
            omissions.insert("chunk_digest_mismatch".to_owned());
            failed = true;
        }
        expected_start = chunk.byte_end;
    }
    if expected_start != request.tree.len() {
        omissions.insert("chunk_missing".to_owned());
        if !failed {
            integrity = Integrity::Clipped;
        }
    }
    match request.source_complete {
        Some(true) => {}
        Some(false) => {
            omissions.insert("source_clipped".to_owned());
            if !failed {
                integrity = Integrity::Clipped;
            }
        }
        None => {
            omissions.insert("source_completeness_unknown".to_owned());
            if !failed {
                integrity = Integrity::Unknown;
            }
        }
    }
    let source_set_digest = digest(source_set.as_bytes());
    let mut out = Outcome {
        request,
        scope_digest,
        requirements_digest,
        source_set_digest,
        omissions,
        occurrences: Vec::new(),
        groups: Vec::new(),
        warnings: Vec::new(),
        unparsed_lines: Vec::new(),
        continuation: None,
        integrity,
    };
    if failed {
        out.integrity = Integrity::Corrupt;
        return out.finish();
    }

    // Caps only shorten the parsed prefix. It ends on a complete line inside
    // both the byte cap and the last attested chunk, so a cap can never cut a
    // multi-byte character or turn a half line into a node.
    let mut limit = request.tree.len();
    if request.tree.len() > caps.bytes {
        out.omissions.insert("scope_byte_cap".to_owned());
        out.integrity = Integrity::Clipped;
        limit = limit.min(caps.bytes);
    }
    if request.chunks.len() > caps.chunks {
        out.omissions.insert("chunk_cap".to_owned());
        out.integrity = Integrity::Clipped;
        let attested_end = caps
            .chunks
            .checked_sub(1)
            .map_or(0, |last| request.chunks[last].byte_end);
        limit = limit.min(attested_end);
    }
    let mut parse_end = request.tree.len();
    if limit < request.tree.len() {
        parse_end = complete_line_prefix(&request.tree, limit);
        out.continuation = Some((
            chunk_containing(&request.chunks, parse_end),
            request.tree[..parse_end].chars().count(),
        ));
    }
    let index = out.parse(&request.tree[..parse_end], caps);
    out.build_groups(&index);
    out.finish()
}

/// Per-node positions computed once during the single parse pass.
struct Index {
    nearest_control: Vec<Option<usize>>,
    subtree_end: Vec<usize>,
}

struct Outcome<'a> {
    request: &'a Request,
    scope_digest: String,
    requirements_digest: String,
    source_set_digest: String,
    omissions: BTreeSet<String>,
    occurrences: Vec<Occurrence>,
    groups: Vec<ChoiceGroup>,
    warnings: Vec<Warning>,
    unparsed_lines: Vec<u32>,
    continuation: Option<(u32, usize)>,
    integrity: Integrity,
}

impl Outcome<'_> {
    fn warn(&mut self, line: u32, issue: &'static str, caps: &Caps) {
        self.omissions.insert(issue.to_owned());
        if self.warnings.len() < caps.diagnostics {
            self.warnings.push(Warning { line, issue });
        } else {
            self.omissions.insert("warning_cap".to_owned());
        }
    }

    /// Single pass over the attested prefix. Parents, nearest controls and
    /// group membership are index based, so work is linear in lines plus nodes.
    fn parse(&mut self, prefix: &str, caps: Caps) -> Index {
        let mut stack: Vec<(usize, usize)> = Vec::new(); // (depth, node index)
        let mut nearest_control: Vec<Option<usize>> = Vec::new();
        let mut subtree_end: Vec<usize> = Vec::new();
        let mut offset = 0usize; // codepoints, counting every terminator
        let mut at = 0usize; // bytes
        let mut number = 0u32;
        while at < prefix.len() {
            let raw = &prefix[at..at + line_len(&prefix[at..])];
            number += 1;
            let text = raw.trim_end_matches(['\r', '\n']);
            let advance = raw.chars().count();
            let marker = is_truncation_marker(text);
            let Some(parsed) = parse_line(text) else {
                if marker {
                    self.warn(number, "source_truncation_marker", &caps);
                    self.integrity = Integrity::Clipped;
                }
                if !py_strip(text).is_empty() {
                    self.omissions.insert("unrecognized_line".to_owned());
                    if self.unparsed_lines.len() < caps.diagnostics {
                        self.unparsed_lines.push(number);
                    } else {
                        self.omissions.insert("unparsed_line_cap".to_owned());
                    }
                }
                offset += advance;
                at += raw.len();
                continue;
            };
            if self.occurrences.len() >= caps.nodes {
                self.omissions.insert("node_cap".to_owned());
                self.continuation = Some((chunk_containing(&self.request.chunks, at), offset));
                break;
            }
            if marker {
                self.warn(number, "source_truncation_marker", &caps);
                self.integrity = Integrity::Clipped;
            }
            for issue in &parsed.warnings {
                self.warn(number, issue, &caps);
            }
            while let Some(&(depth, popped)) = stack.last() {
                if depth < parsed.depth {
                    break;
                }
                subtree_end[popped] = self.occurrences.len();
                stack.pop();
            }
            if parsed.depth > 0
                && stack
                    .last()
                    .is_none_or(|(depth, _)| parsed.depth > depth + 1)
            {
                self.warn(number, "indentation_gap", &caps);
            }
            let parent = stack.last().map(|(_, index)| *index);

            // Classify on the full source role; caps only shorten what is kept.
            let occurrence_kind = if is_control_role(&parsed.role) {
                "control"
            } else if parsed.role == "option" {
                "option"
            } else {
                "element"
            };
            let blank = py_strip(&parsed.label).is_empty();
            let mut role = parsed.role;
            if role.chars().count() > caps.role {
                self.omissions.insert("role_cap".to_owned());
                role = role.chars().take(caps.role).collect();
            }
            let mut label = parsed.label;
            let label_capped = label.chars().count() > caps.label;
            if label_capped {
                self.omissions.insert("label_cap".to_owned());
                label = label.chars().take(caps.label).collect();
            }
            let mut bid = parsed.bid;
            if bid.as_ref().is_some_and(|b| b.chars().count() > caps.bid) {
                self.omissions.insert("bid_cap".to_owned());
                bid = bid.map(|b| b.chars().take(caps.bid).collect());
            }
            let selector = format!("line:{number}");
            if selector.chars().count() > caps.selector {
                self.omissions.insert("selector_cap".to_owned());
            }
            let excerpt = if text.chars().count() > caps.excerpt {
                self.omissions.insert("excerpt_cap".to_owned());
                text.chars().take(caps.excerpt).collect()
            } else {
                text.to_owned()
            };

            let index = self.occurrences.len();
            let control_above = parent.and_then(|p| {
                if self.occurrences[p].occurrence_kind == "control" {
                    Some(p)
                } else {
                    nearest_control[p]
                }
            });
            let binding_status = match occurrence_kind {
                "control" => Binding::Bound,
                "option" if control_above.is_some() => Binding::Bound,
                "option" => Binding::Unresolved,
                _ if parent.is_some() => Binding::Inferred,
                _ => Binding::Bound,
            };
            self.occurrences.push(Occurrence {
                occurrence_kind,
                search_label: search_label(&label),
                raw_label: label,
                label_capped,
                raw_role: role,
                bid,
                source_order: index as u32,
                depth: parsed.depth,
                selector,
                parent_selector: parent.map(|p| self.occurrences[p].selector.clone()),
                parent_inferred: parent.is_some(),
                binding_status,
                selected: parsed.selected,
                disabled: parsed.disabled,
                blank: if blank { "true" } else { "false" },
                line: number,
                char_start: offset,
                char_end: offset + text.chars().count(),
                excerpt,
            });
            nearest_control.push(control_above);
            subtree_end.push(0);
            stack.push((parsed.depth, index));
            offset += advance;
            at += raw.len();
        }
        let total = self.occurrences.len();
        for (_, open) in stack {
            subtree_end[open] = total;
        }
        Index {
            nearest_control,
            subtree_end,
        }
    }
}

impl Outcome<'_> {
    /// Reference `read_control_options`: options whose nearest control
    /// ancestor is this control, in source order; the boundary is the end of
    /// the control's indentation subtree.
    fn build_groups(&mut self, index: &Index) {
        let mut members: BTreeMap<usize, Vec<String>> = BTreeMap::new();
        for (position, node) in self.occurrences.iter().enumerate() {
            if node.occurrence_kind == "option" {
                if let Some(control) = index.nearest_control[position] {
                    members
                        .entry(control)
                        .or_default()
                        .push(node.selector.clone());
                }
            }
        }
        let total = self.occurrences.len();
        for (position, control) in self.occurrences.iter().enumerate() {
            if control.occurrence_kind != "control" {
                continue;
            }
            let option_selectors = members.remove(&position).unwrap_or_default();
            if option_selectors.is_empty() {
                self.omissions
                    .insert("no_observed_option_children".to_owned());
            }
            let boundary = if index.subtree_end[position] < total {
                "following_sibling_or_ancestor"
            } else {
                "end_of_captured_source"
            };
            self.groups.push(ChoiceGroup {
                control_selector: control.selector.clone(),
                binding_revision: self.request.binding_revision.clone(),
                membership_policy: "source_subtree",
                boundary_method: boundary,
                ordering_basis: "source_order",
                binding_status: control.binding_status,
                option_selectors,
            });
        }
    }

    fn finish(mut self) -> Attestation {
        let request = self.request;
        let unknown_requirement = request
            .requirements
            .iter()
            .any(|r| !CLOSED_REQUIREMENTS.contains(&r.as_str()));
        if unknown_requirement {
            self.omissions.insert("unknown_requirement".to_owned());
        }
        let structural = if self.integrity == Integrity::Corrupt {
            Structural::Failed
        } else if self.integrity != Integrity::Verified
            || self.continuation.is_some()
            || self.omissions.iter().any(|o| {
                !matches!(
                    o.as_str(),
                    "no_observed_option_children" | "unknown_requirement"
                )
            })
        {
            Structural::Partial
        } else {
            Structural::Complete
        };
        let semantic = if structural == Structural::Failed || unknown_requirement {
            Semantic::NotAttempted
        } else if structural == Structural::Partial
            || self.omissions.contains("no_observed_option_children")
        {
            Semantic::Partial
        } else {
            Semantic::Established
        };
        let nodes = self.occurrences.len() as u32;
        Attestation {
            schema: ATTESTATION_VERSION,
            view: request.scope.view.clone(),
            source_ref: request.source_ref.clone(),
            identity: Identity {
                scope_digest: self.scope_digest.clone(),
                source_set_digest: self.source_set_digest.clone(),
                extractor_version: ATTESTATION_VERSION,
                binding_revision: request.binding_revision.clone(),
                requirements_digest: self.requirements_digest.clone(),
            },
            occurrences: self.occurrences,
            groups: self.groups,
            warnings: self.warnings,
            unparsed_lines: self.unparsed_lines,
            coverage: Coverage {
                coverage_schema: COVERAGE_SCHEMA,
                scope_digest: self.scope_digest,
                source_set_digest: self.source_set_digest,
                extractor_version: ATTESTATION_VERSION,
                binding_revision: request.binding_revision.clone(),
                requirements_digest: self.requirements_digest,
                source_integrity: self.integrity,
                structural_coverage: structural,
                semantic_coverage: semantic,
                omissions: self.omissions,
                continuation: self.continuation,
                parsed_nodes: nodes,
                chunk_count: request.chunks.len() as u32,
                expected_item_count: nodes,
            },
        }
    }
}

/// Closed label binding: exactly one control with this label binds; multiple
/// candidates are ambiguous; none is unresolved. A control whose stored label
/// was shortened by the label cap never binds: its full label is unknown, so
/// it can only make a match uncertain, never certain.
pub(crate) fn bind_by_label<'a>(
    attestation: &'a Attestation,
    label: &str,
) -> (Binding, Vec<&'a ChoiceGroup>) {
    let control = |group: &ChoiceGroup| {
        attestation
            .occurrences
            .iter()
            .find(|o| o.selector == group.control_selector)
    };
    let candidates: Vec<_> = attestation
        .groups
        .iter()
        .filter(|g| control(g).is_some_and(|o| !o.label_capped && o.raw_label == label))
        .collect();
    let uncertain = attestation.groups.iter().any(|g| {
        control(g).is_some_and(|o| o.label_capped && label.starts_with(o.raw_label.as_str()))
    });
    match (candidates.len(), uncertain) {
        (1, false) => (Binding::Bound, candidates),
        (0, false) => (Binding::Unresolved, candidates),
        (0, true) => (Binding::Unresolved, candidates),
        _ => (Binding::Ambiguous, candidates),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(view: &str) -> Scope {
        Scope {
            namespace: "synthetic.software".into(),
            trajectory: "traj-1".into(),
            state: 0,
            view: view.into(),
            scope_selector: "root".into(),
        }
    }

    fn chunks_at(tree: &str, cuts: &[usize]) -> Vec<Chunk> {
        let bytes = tree.as_bytes();
        let mut bounds = vec![0usize];
        bounds.extend(cuts.iter().copied());
        bounds.push(bytes.len());
        bounds
            .windows(2)
            .enumerate()
            .filter(|(_, w)| w[0] < w[1])
            .map(|(i, w)| Chunk {
                ordinal: i as u32,
                byte_start: w[0],
                byte_end: w[1],
                sha256: digest(&bytes[w[0]..w[1]]),
            })
            .collect()
    }

    fn request_chunked(tree: &str, complete: Option<bool>, cuts: &[usize]) -> Request {
        let chunks = chunks_at(tree, cuts);
        Request {
            scope: scope("view-1"),
            source_ref: "fixture:tree".into(),
            source_complete: complete,
            tree: tree.to_owned(),
            declared: Declared {
                sha256: digest(tree.as_bytes()),
                len: tree.len(),
                chunks: chunks.len(),
            },
            chunks,
            binding_revision: "binding-1".into(),
            requirements: ["flags", "options", "parents"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }
    }

    fn request(tree: &str, complete: Option<bool>) -> Request {
        request_chunked(tree, complete, &[])
    }

    fn run(tree: &str) -> Attestation {
        attest(&request(tree, Some(true)), Caps::default())
    }

    const POSITIVE: &str =
        "combobox \"Priority\" required\n\toption \"High\" selected=True\n\toption \"Low\"\ncombobox \"Area\"\n";

    // Reference-generated expectations (see the generator's provenance block).

    const REFERENCE_SHA256: &str =
        "f4eee3b4428d860e45621a1c11df35909d8e80f61becd9e236cf2806655fd808";

    fn expected() -> serde_json::Value {
        serde_json::from_str(include_str!("fixtures/software/reference-expected.json")).unwrap()
    }

    #[test]
    fn reference_expected_carries_provenance() {
        let p = &expected()["provenance"];
        assert_eq!(p["reference_sha256"], REFERENCE_SHA256);
        assert_eq!(p["reference_version"], "native.software-observations/0.1");
        assert_eq!(p["offset_unit"], "unicode_codepoint");
        assert!(p["generator"]
            .as_str()
            .unwrap()
            .ends_with("generate_reference_expected.py"));
        assert!(p["flag_mapping"]
            .as_str()
            .unwrap()
            .contains("'False' -> false"));
    }

    #[test]
    fn matches_reference_on_every_committed_case() {
        let all = expected();
        let mut cases = 0;
        for (name, case) in all.as_object().unwrap() {
            if name == "provenance" {
                continue;
            }
            cases += 1;
            let tree = case["tree"].as_str().unwrap();
            assert_eq!(
                digest(tree.as_bytes()),
                case["tree_sha256"].as_str().unwrap(),
                "{name}"
            );
            let a = run(tree);
            let nodes = case["nodes"].as_array().unwrap();
            assert_eq!(a.occurrences.len(), nodes.len(), "{name} node count");
            for (i, node) in nodes.iter().enumerate() {
                let ours = &a.occurrences[i];
                let ctx = format!("{name}[{i}]");
                assert_eq!(ours.raw_role, node["role"].as_str().unwrap(), "{ctx} role");
                assert_eq!(
                    ours.raw_label,
                    node["label"].as_str().unwrap(),
                    "{ctx} label"
                );
                assert_eq!(
                    ours.source_order as u64,
                    node["source_order"].as_u64().unwrap(),
                    "{ctx}"
                );
                assert_eq!(
                    ours.depth as u64,
                    node["depth"].as_u64().unwrap(),
                    "{ctx} depth"
                );
                let parent = node["parent"]
                    .as_u64()
                    .map(|p| a.occurrences[p as usize].selector.clone());
                assert_eq!(ours.parent_selector, parent, "{ctx} parent");
                assert_eq!(ours.bid.as_deref(), node["bid"].as_str(), "{ctx} bid");
                for (field, got) in [("selected", ours.selected), ("disabled", ours.disabled)] {
                    let want = match node[field].as_bool() {
                        Some(true) => "true",
                        Some(false) => "false",
                        None => "unknown",
                    };
                    assert_eq!(got, want, "{ctx} {field}");
                }
                assert_eq!(
                    ours.line as u64,
                    node["line"].as_u64().unwrap(),
                    "{ctx} line"
                );
                assert_eq!(
                    ours.char_start as u64,
                    node["char_start"].as_u64().unwrap(),
                    "{ctx} start"
                );
                assert_eq!(
                    ours.char_end as u64,
                    node["char_end"].as_u64().unwrap(),
                    "{ctx} end"
                );
                assert_eq!(
                    ours.excerpt,
                    node["exact"].as_str().unwrap(),
                    "{ctx} excerpt"
                );
            }
            // Group membership and subtree boundary.
            let groups = case["groups"].as_array().unwrap();
            assert_eq!(a.groups.len(), groups.len(), "{name} group count");
            for (g, want) in a.groups.iter().zip(groups) {
                let control = want["control"].as_u64().unwrap() as usize;
                assert_eq!(
                    g.control_selector, a.occurrences[control].selector,
                    "{name}"
                );
                let options: Vec<_> = want["options"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|o| a.occurrences[o.as_u64().unwrap() as usize].selector.clone())
                    .collect();
                assert_eq!(g.option_selectors, options, "{name} options");
                assert_eq!(
                    g.boundary_method,
                    want["boundary"].as_str().unwrap(),
                    "{name} boundary"
                );
            }
            // Unparsed lines and warnings (as sorted sets, not an order contract).
            let cov = &case["coverage"];
            let unparsed: Vec<u32> = cov["unparsed_nonempty_lines"]
                .as_array()
                .unwrap()
                .iter()
                .map(|l| l.as_u64().unwrap() as u32)
                .collect();
            assert_eq!(a.unparsed_lines, unparsed, "{name} unparsed");
            let mut want: Vec<(u32, String)> = cov["structural_warnings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|w| {
                    (
                        w["line"].as_u64().unwrap() as u32,
                        w["issue"].as_str().unwrap().to_owned(),
                    )
                })
                .collect();
            let mut got: Vec<(u32, String)> = a
                .warnings
                .iter()
                .map(|w| (w.line, w.issue.to_owned()))
                .collect();
            want.sort();
            got.sort();
            assert_eq!(got, want, "{name} warnings");
            assert_eq!(
                a.coverage.parsed_nodes as u64,
                cov["parsed_nodes"].as_u64().unwrap()
            );
            // Anything the reference warns about or cannot parse is never Complete.
            if !want.is_empty() || !unparsed.is_empty() {
                assert_eq!(
                    a.coverage.structural_coverage,
                    Structural::Partial,
                    "{name}"
                );
            }
        }
        assert!(cases >= 10);
    }

    // Declared source, integrity and verdicts.

    #[test]
    fn unknown_or_absent_source_completeness_is_not_complete() {
        let a = attest(&request(POSITIVE, None), Caps::default());
        assert_eq!(a.coverage.source_integrity, Integrity::Unknown);
        assert_eq!(a.coverage.structural_coverage, Structural::Partial);
        assert_ne!(a.coverage.semantic_coverage, Semantic::Established);
        let b = run("");
        assert_eq!(b.coverage.source_integrity, Integrity::Clipped);
        assert!(b.coverage.omissions.contains("no_attested_chunks"));
    }

    #[test]
    fn forged_declaration_and_uppercase_digest_are_corrupt() {
        let mut req = request(POSITIVE, Some(true));
        req.declared.sha256 = digest(b"other bytes");
        req.declared.len = b"other bytes".len();
        let a = attest(&req, Caps::default());
        assert_eq!(a.coverage.source_integrity, Integrity::Corrupt);
        assert_eq!(a.coverage.structural_coverage, Structural::Failed);
        assert!(a.occurrences.is_empty());
        let mut upper = request(POSITIVE, Some(true));
        upper.declared.sha256 = upper.declared.sha256.to_uppercase();
        let b = attest(&upper, Caps::default());
        assert!(b.coverage.omissions.contains("declared_digest_invalid"));
        assert_eq!(b.coverage.structural_coverage, Structural::Failed);
    }

    #[test]
    fn verdict_rules_for_flags_options_and_requirements() {
        let a = run("combobox \"C\"\n\toption \"A\" selected=False\n");
        assert_eq!(a.occurrences[1].selected, "false");
        assert_eq!(a.coverage.structural_coverage, Structural::Complete);
        assert_eq!(a.coverage.semantic_coverage, Semantic::Established);
        let b = run("combobox \"Empty\"\n");
        assert_eq!(b.coverage.structural_coverage, Structural::Complete);
        assert_eq!(b.coverage.semantic_coverage, Semantic::Partial);
        let mut req = request(POSITIVE, Some(true));
        req.requirements.insert("visual_regions".into());
        let c = attest(&req, Caps::default());
        assert_eq!(c.coverage.semantic_coverage, Semantic::NotAttempted);
        let d = run("combobox \"C\"\n\t\toption \"Gap\"\n\toption \"Bad\n");
        assert!(d.coverage.omissions.contains("indentation_gap"));
        assert_eq!(d.coverage.structural_coverage, Structural::Partial);
    }

    // P1-P3: byte and chunk caps keep a complete-line, attested prefix.

    const UNICODE_TREE: &str =
        "combobox \"caf\u{e9}\"\n\toption \"\u{e9}\"\n\toption \"\u{fc}ber\"\n";

    #[test]
    fn byte_cap_never_panics_or_fabricates_a_node() {
        let full = run(UNICODE_TREE);
        assert_eq!(full.occurrences.len(), 3);
        for cap in 0..=UNICODE_TREE.len() + 1 {
            let caps = Caps {
                bytes: cap,
                ..Caps::default()
            };
            let a = attest(&request(UNICODE_TREE, Some(true)), caps);
            // Every emitted node is exactly the uncapped node, never a fragment.
            assert_eq!(
                a.occurrences[..],
                full.occurrences[..a.occurrences.len()],
                "cap {cap}"
            );
            let fitted: usize = UNICODE_TREE
                .split_inclusive('\n')
                .scan(0usize, |sum, l| {
                    *sum += l.len();
                    Some(*sum)
                })
                .take_while(|end| *end <= cap)
                .count();
            if cap >= UNICODE_TREE.len() {
                assert_eq!(a.occurrences.len(), 3, "cap {cap}");
                assert_eq!(a.coverage.continuation, None);
                continue;
            }
            assert_eq!(a.occurrences.len(), fitted, "cap {cap}");
            assert_eq!(
                a.coverage.structural_coverage,
                Structural::Partial,
                "cap {cap}"
            );
            assert!(a.coverage.omissions.contains("scope_byte_cap"));
            let prefix: String = UNICODE_TREE.split_inclusive('\n').take(fitted).collect();
            assert_eq!(
                a.coverage.continuation,
                Some((0, prefix.chars().count())),
                "cap {cap}"
            );
        }
    }

    #[test]
    fn continuation_names_the_chunk_that_contains_the_cut() {
        let tree = "combobox \"A\"\n\toption \"Long label here\"\n";
        // Cuts at byte 13 (end of line 1) fall in the second chunk.
        let req = request_chunked(tree, Some(true), &[5]);
        let byte_capped = attest(
            &req,
            Caps {
                bytes: 25,
                ..Caps::default()
            },
        );
        assert_eq!(byte_capped.occurrences.len(), 1);
        assert_eq!(byte_capped.coverage.continuation, Some((1, 13)));
        let node_capped = attest(
            &req,
            Caps {
                nodes: 1,
                ..Caps::default()
            },
        );
        assert_eq!(node_capped.occurrences.len(), 1);
        assert!(node_capped.coverage.omissions.contains("node_cap"));
        assert_eq!(node_capped.coverage.continuation, Some((1, 13)));
    }

    #[test]
    fn chunk_cap_stops_parsing_at_the_attested_prefix_in_codepoints() {
        // Chunk 0 ends mid-way through line 2, so only line 1 is attested.
        let cut = UNICODE_TREE.find("\toption \"\u{e9}\"").unwrap() + 4;
        let req = request_chunked(UNICODE_TREE, Some(true), &[cut]);
        let a = attest(
            &req,
            Caps {
                chunks: 1,
                ..Caps::default()
            },
        );
        assert_eq!(a.occurrences.len(), 1);
        assert!(a.coverage.omissions.contains("chunk_cap"));
        assert_eq!(a.coverage.structural_coverage, Structural::Partial);
        let line1 = "combobox \"caf\u{e9}\"\n";
        assert!(line1.len() > line1.chars().count());
        assert_eq!(a.coverage.continuation, Some((0, line1.chars().count())));
        let none = attest(
            &req,
            Caps {
                chunks: 0,
                ..Caps::default()
            },
        );
        assert!(none.occurrences.is_empty());
        assert_eq!(none.coverage.continuation, Some((0, 0)));
    }

    #[test]
    fn node_and_diagnostic_caps_bound_output() {
        let many: String = (0..50).map(|i| format!("combobox \"C{i}\"\n")).collect();
        let a = attest(
            &request(&many, Some(true)),
            Caps {
                nodes: 10,
                ..Caps::default()
            },
        );
        assert_eq!(a.occurrences.len(), 10);
        assert_eq!(a.coverage.structural_coverage, Structural::Partial);
        assert!(a.coverage.omissions.contains("node_cap"));
        assert_eq!(
            a.coverage.continuation.map(|c| c.1),
            Some(a.occurrences[9].char_end + 1)
        );
        let junk = "???\n".repeat(30);
        let caps = Caps {
            diagnostics: 5,
            ..Caps::default()
        };
        let b = attest(&request(&junk, Some(true)), caps);
        assert_eq!(b.unparsed_lines.len(), 5);
        assert!(b.coverage.omissions.contains("unparsed_line_cap"));
        assert_eq!(b.coverage.structural_coverage, Structural::Partial);
    }

    // P4/P5: lexing the reference refuses or reads differently.

    #[test]
    fn lexing_refuses_what_the_reference_refuses() {
        let a = run("combobox Priority required\n");
        assert_eq!(a.occurrences[0].raw_label, "");
        assert_eq!(a.coverage.structural_coverage, Structural::Partial);
        let b = run("combobox\"X\"\n[a-b] combobox \"Y\"\n[ab]combobox \"Z\"\n");
        assert!(b.occurrences.is_empty());
        assert_eq!(b.unparsed_lines, vec![1, 2, 3]);
        let c = run("combobox \"C\" a,,b\n\toption \"O\" selected = True\n");
        assert_eq!(c.occurrences[1].selected, "unknown");
        assert!(c.coverage.omissions.contains("unrecognized_property_span"));
        let d = run("\tcombobox \"Indented\"\n");
        assert!(d.coverage.omissions.contains("indentation_gap"));
    }

    #[test]
    fn escapes_keep_invalid_spelling_and_combine_valid_pairs() {
        let (pair, errs) = decode_ax("\\ud83d\\ude00");
        assert_eq!((pair.as_str(), errs.len()), ("\u{1f600}", 0));
        let (lone, errs) = decode_ax("a\\ud83dz");
        assert_eq!(lone, "a\\ud83dz");
        assert_eq!(errs, vec!["unpaired_surrogate"]);
        let (bad, errs) = decode_ax("\\q\\");
        assert_eq!(bad, "\\q\\");
        assert_eq!(errs, vec!["unsupported_escape", "trailing_escape"]);
    }

    #[test]
    fn crlf_offsets_count_terminators_and_exclude_them_from_ends() {
        let a = run("combobox \"A\"\r\n\toption \"B\"\r\ncombobox \"C\"");
        assert_eq!(a.occurrences[0].char_end, 12);
        assert_eq!(a.occurrences[1].char_start, 14);
        assert_eq!(a.occurrences[2].char_start, 14 + 11 + 2);
        assert_eq!(a.occurrences[2].line, 3);
    }

    // P6-P8: classification and binding use the full source values.

    #[test]
    fn caps_never_change_kind_or_bind_a_capped_control() {
        let caps = Caps {
            role: 8,
            label: 8,
            bid: 3,
            ..Caps::default()
        };
        let a = attest(
            &request("comboboxlong \"x\"\n\toption \"y\"\n", Some(true)),
            caps,
        );
        assert_eq!(a.occurrences[0].raw_role, "combobox");
        assert_eq!(a.occurrences[0].occurrence_kind, "element");
        assert!(a.groups.is_empty());
        assert_eq!(a.occurrences[1].binding_status, Binding::Unresolved);
        assert!(a.coverage.omissions.contains("role_cap"));
        let tree = "combobox \"Priority High\"\n\toption \"x\"\ncombobox \"Priority\"\n";
        let b = attest(&request(tree, Some(true)), caps);
        assert!(b.occurrences[0].label_capped);
        assert_eq!(bind_by_label(&b, "Priority").0, Binding::Ambiguous);
        assert_eq!(bind_by_label(&b, "Priority High").0, Binding::Unresolved);
        assert_eq!(b.coverage.semantic_coverage, Semantic::Partial);
        let only = attest(&request("combobox \"Priority High\"\n", Some(true)), caps);
        assert_eq!(bind_by_label(&only, "Priority").0, Binding::Unresolved);
        let c = attest(&request("[abcdef] combobox \"A\"\n", Some(true)), caps);
        assert_eq!(c.occurrences[0].bid.as_deref(), Some("abc"));
        assert!(c.coverage.omissions.contains("bid_cap"));
        assert_eq!(c.coverage.structural_coverage, Structural::Partial);
    }

    #[test]
    fn blank_follows_the_label_not_the_line() {
        let a = run("combobox \"x\"\ncombobox \"  \"\ncombobox\n");
        let blank: Vec<_> = a.occurrences.iter().map(|o| o.blank).collect();
        assert_eq!(blank, vec!["false", "true", "true"]);
    }

    #[test]
    fn duplicate_labels_bind_ambiguously_and_missing_is_unresolved() {
        let a = run("combobox \"Dup\"\ncombobox \"Dup\"\n");
        assert_eq!(bind_by_label(&a, "Dup").0, Binding::Ambiguous);
        assert_eq!(bind_by_label(&a, "Absent").0, Binding::Unresolved);
        assert_eq!(
            bind_by_label(&run("combobox \"Only\"\n"), "Only").0,
            Binding::Bound
        );
    }

    // P9: identity.

    #[test]
    fn failed_or_empty_manifests_do_not_share_a_coverage_key() {
        let key = |tree: &str, declared: &str| {
            let mut req = request(tree, Some(true));
            req.chunks.clear();
            req.declared.chunks = 0;
            req.declared.sha256 = declared.to_owned();
            attest(&req, Caps::default()).coverage.source_set_digest
        };
        let d1 = digest(b"one");
        let d2 = digest(b"two");
        assert_ne!(key("combobox \"A\"\n", &d1), key("combobox \"B\"\n", &d1));
        assert_ne!(key("combobox \"A\"\n", &d1), key("combobox \"A\"\n", &d2));
        assert_eq!(key("combobox \"A\"\n", &d1), key("combobox \"A\"\n", &d1));
        assert_ne!(key("", &d1), key("", &d2));
        let one = run(POSITIVE);
        let two = run("combobox \"Priority\"\n");
        assert_eq!(one.identity.scope_digest, two.identity.scope_digest);
        assert_ne!(
            one.coverage.source_set_digest,
            two.coverage.source_set_digest
        );
    }

    // P10: parent and control lookup is index based.

    #[test]
    fn deep_chain_groups_every_option_under_its_control() {
        let depth = 3000usize;
        let mut tree = String::from("combobox \"Deep\"\n");
        for d in 1..depth {
            tree.push_str(&"\t".repeat(d));
            tree.push_str("option \"o\"\n");
        }
        let caps = Caps {
            bytes: usize::MAX,
            excerpt: usize::MAX,
            nodes: depth,
            ..Caps::default()
        };
        let a = attest(&request(&tree, Some(true)), caps);
        assert_eq!(a.occurrences.len(), depth);
        assert_eq!(a.groups[0].option_selectors.len(), depth - 1);
        assert_eq!(a.groups[0].boundary_method, "end_of_captured_source");
        assert_eq!(a.coverage.structural_coverage, Structural::Complete);
    }
}
