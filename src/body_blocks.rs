//! Pure, fallible body-block extraction (E3 M3 parser increment).
//!
//! A caller must classify the stored body before calling this module. A JSON
//! non-string value that `record_body::coerce_body` serialized into TEXT is
//! [`BodyFormat::Opaque`], never Markdown inferred from its textual spelling.
//! This module owns no persistence, SQL relation, or cross-edit block identity.
//!
//! Blocks follow top-level GFM mdast nodes. Their source spans partition the
//! original body byte-for-byte: inter-node whitespace belongs to the preceding
//! block, and leading whitespace is an `interstitial` block. Each span is
//! divided into UTF-8-safe chunks of at most 32 KiB. Even if every source
//! byte JSON-escapes to six bytes, one encoded text cell stays under the
//! governed 256 KiB cell ceiling. `block_index` and heading ordinals are only
//! meaningful within this body revision; they are not durable references.
//! Future projectors must derive [`BodyFormat`] from the body-writing event's
//! JSON value, not guess it from the coerced `records.body` TEXT.

use markdown::{mdast::Node, to_mdast, Constructs, ParseOptions};

/// The caller's explicit interpretation of the stored body bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyFormat {
    /// A body originally supplied as a JSON string containing Markdown text.
    Markdown,
    /// A non-string body coerced to text, or text deliberately treated as opaque.
    Opaque,
}

/// One ancestor heading, distinguished even when titles repeat.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct HeadingSegment {
    pub depth: u8,
    /// A bounded display excerpt. The ordinal, rather than this possibly
    /// truncated title, identifies the heading within this body revision.
    pub title: String,
    pub title_truncated: bool,
    /// The heading's zero-based block ordinal in this body revision.
    pub block_index: usize,
}

/// One lossless chunk of a top-level block's source span.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyBlockChunk {
    pub block_index: usize,
    pub chunk_index: usize,
    pub chunk_count: usize,
    pub heading_path: Vec<HeadingSegment>,
    pub block_kind: &'static str,
    pub text: String,
    pub start_offset: usize,
    pub end_offset: usize,
}

/// A conservative raw-byte bound; worst-case JSON escaping is sixfold.
pub const MAX_CHUNK_TEXT_BYTES: usize = 32 * 1024;
pub const MAX_HEADING_TITLE_CHARS: usize = 120;
/// Transactional physical projections refuse oversized bodies before deleting
/// prior rows. Ordinary record-body writers currently have no global cap.
pub const MAX_PROJECTED_BODY_BYTES: usize = 16 * 1024 * 1024;
/// A pathological body with millions of tiny blocks must not issue unbounded
/// projection inserts inside one event transaction.
pub const MAX_PROJECTED_CHUNKS: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractError {
    pub message: String,
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "body block extraction failed: {}", self.message)
    }
}

impl std::error::Error for ExtractError {}

/// Extract source-preserving block chunks. SQL NULL has no blocks.
///
/// Parse failures or invalid source positions are errors. Callers must abort
/// their write/backfill rather than replace prior rows with an empty set.
pub fn extract_body_blocks(
    body: Option<&str>,
    format: BodyFormat,
) -> Result<Vec<BodyBlockChunk>, ExtractError> {
    extract_body_blocks_inner(body, format, None)
}

fn extract_body_blocks_inner(
    body: Option<&str>,
    format: BodyFormat,
    chunk_limit: Option<usize>,
) -> Result<Vec<BodyBlockChunk>, ExtractError> {
    let Some(body) = body else {
        return Ok(Vec::new());
    };
    if body.is_empty() {
        return Ok(Vec::new());
    }
    if format == BodyFormat::Opaque {
        let mut out = Vec::new();
        emit_chunks(body, 0, body.len(), 0, &[], "opaque", &mut out);
        check_chunk_limit(&out, chunk_limit)?;
        return Ok(out);
    }

    let options = ParseOptions {
        constructs: Constructs::gfm(),
        ..ParseOptions::default()
    };
    let root = to_mdast(body, &options).map_err(|message| ExtractError {
        message: message.to_string(),
    })?;
    let Node::Root(root) = root else {
        return Err(ExtractError {
            message: "Markdown parser returned a non-root node".into(),
        });
    };
    let starts = validate_starts(&root.children, body)?;
    let mut out = Vec::new();
    let mut block_index = 0;
    if starts.first().copied().unwrap_or(body.len()) > 0 {
        emit_chunks(
            body,
            0,
            starts.first().copied().unwrap_or(body.len()),
            block_index,
            &[],
            "interstitial",
            &mut out,
        );
        check_chunk_limit(&out, chunk_limit)?;
        block_index += 1;
    }
    let mut heading_path = Vec::<HeadingSegment>::new();
    for (index, node) in root.children.iter().enumerate() {
        if let Node::Heading(heading) = node {
            while heading_path
                .last()
                .is_some_and(|ancestor| ancestor.depth >= heading.depth)
            {
                heading_path.pop();
            }
            let (title, title_truncated) = heading_title(&heading.children);
            heading_path.push(HeadingSegment {
                depth: heading.depth,
                title,
                title_truncated,
                block_index,
            });
        }
        let end = starts.get(index + 1).copied().unwrap_or(body.len());
        emit_chunks(
            body,
            starts[index],
            end,
            block_index,
            &heading_path,
            block_kind(node),
            &mut out,
        );
        check_chunk_limit(&out, chunk_limit)?;
        block_index += 1;
    }
    Ok(out)
}

/// Admission wrapper for persisted rows. Its limits are explicit engine
/// policy, not claims about the general record-body write surface.
pub fn extract_projectable_body_blocks(
    body: Option<&str>,
    format: BodyFormat,
) -> Result<Vec<BodyBlockChunk>, ExtractError> {
    if body.is_some_and(|body| body.len() > MAX_PROJECTED_BODY_BYTES) {
        return Err(ExtractError {
            message: format!(
                "body exceeds the {MAX_PROJECTED_BODY_BYTES}-byte block projection limit"
            ),
        });
    }
    extract_body_blocks_inner(body, format, Some(MAX_PROJECTED_CHUNKS))
}

fn check_chunk_limit(chunks: &[BodyBlockChunk], limit: Option<usize>) -> Result<(), ExtractError> {
    if let Some(limit) = limit {
        if chunks.len() > limit {
            return Err(ExtractError {
                message: format!("body has more than {limit} chunks, above the {limit}-chunk block projection limit"),
            });
        }
    }
    Ok(())
}

/// Render only the heading's human-readable phrasing, with a hard size bound.
/// `markdown`'s `Node::to_string()` drops image alt text and break nodes, so
/// using it here would make image-only headings appear untitled. The raw
/// heading source remains losslessly available in the heading block chunks.
fn heading_title(children: &[Node]) -> (String, bool) {
    fn append(out: &mut String, text: &str, truncated: &mut bool) {
        if *truncated {
            return;
        }
        let remaining = MAX_HEADING_TITLE_CHARS - out.chars().count();
        for (index, ch) in text.chars().enumerate() {
            if index == remaining {
                *truncated = true;
                return;
            }
            out.push(ch);
        }
    }

    fn visit(node: &Node, out: &mut String, truncated: &mut bool) {
        match node {
            Node::Text(value) => append(out, &value.value, truncated),
            Node::InlineCode(value) => append(out, &value.value, truncated),
            Node::InlineMath(value) => append(out, &value.value, truncated),
            Node::Html(value) => append(out, &value.value, truncated),
            Node::MdxTextExpression(value) => append(out, &value.value, truncated),
            Node::Image(value) => append(out, &value.alt, truncated),
            Node::ImageReference(value) => append(out, &value.alt, truncated),
            Node::FootnoteReference(value) => append(
                out,
                value.label.as_deref().unwrap_or(&value.identifier),
                truncated,
            ),
            Node::Break(_) => append(out, " ", truncated),
            _ => {
                if let Some(children) = node.children() {
                    for child in children {
                        visit(child, out, truncated);
                        if *truncated {
                            break;
                        }
                    }
                }
            }
        }
    }

    let mut title = String::new();
    let mut truncated = false;
    for child in children {
        visit(child, &mut title, &mut truncated);
        if truncated {
            break;
        }
    }
    (title, truncated)
}

fn validate_starts(nodes: &[Node], body: &str) -> Result<Vec<usize>, ExtractError> {
    let mut starts = Vec::with_capacity(nodes.len());
    let mut previous_end = 0;
    for node in nodes {
        let position = node.position().ok_or_else(|| ExtractError {
            message: "Markdown block has no source position".into(),
        })?;
        let start = position.start.offset;
        let end = position.end.offset;
        if start >= end
            || end > body.len()
            || !body.is_char_boundary(start)
            || !body.is_char_boundary(end)
            || start < previous_end
        {
            return Err(ExtractError {
                message: format!("Markdown block has invalid source span {start}..{end}"),
            });
        }
        starts.push(start);
        previous_end = end;
    }
    Ok(starts)
}

fn block_kind(node: &Node) -> &'static str {
    match node {
        Node::Heading(_) => "heading",
        Node::Paragraph(_) => "paragraph",
        Node::Code(_) => "code",
        Node::Blockquote(_) => "blockquote",
        Node::List(_) => "list",
        Node::Table(_) => "table",
        Node::Html(_) => "html",
        Node::ThematicBreak(_) => "thematic_break",
        Node::Definition(_) => "definition",
        Node::FootnoteDefinition(_) => "footnote_definition",
        _ => "other",
    }
}

fn emit_chunks(
    source: &str,
    start: usize,
    end: usize,
    block_index: usize,
    heading_path: &[HeadingSegment],
    block_kind: &'static str,
    out: &mut Vec<BodyBlockChunk>,
) {
    let mut boundaries = vec![start];
    let mut cursor = start;
    while cursor < end {
        let mut next = (cursor + MAX_CHUNK_TEXT_BYTES).min(end);
        while !source.is_char_boundary(next) {
            next -= 1;
        }
        // A UTF-8 scalar is at most four bytes, below the chunk budget.
        debug_assert!(next > cursor);
        boundaries.push(next);
        cursor = next;
    }
    let chunk_count = boundaries.len() - 1;
    for (chunk_index, pair) in boundaries.windows(2).enumerate() {
        out.push(BodyBlockChunk {
            block_index,
            chunk_index,
            chunk_count,
            heading_path: heading_path.to_vec(),
            block_kind,
            text: source[pair[0]..pair[1]].to_owned(),
            start_offset: pair[0],
            end_offset: pair[1],
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn markdown(body: &str) -> Vec<BodyBlockChunk> {
        extract_body_blocks(Some(body), BodyFormat::Markdown).unwrap()
    }

    fn source_round_trip(body: &str, chunks: &[BodyBlockChunk]) {
        assert_eq!(chunks.first().map(|chunk| chunk.start_offset), Some(0));
        assert_eq!(
            chunks.last().map(|chunk| chunk.end_offset),
            Some(body.len())
        );
        let reconstructed: String = chunks.iter().map(|chunk| chunk.text.as_str()).collect();
        assert_eq!(reconstructed, body);
        for (index, chunk) in chunks.iter().enumerate() {
            assert_eq!(&body[chunk.start_offset..chunk.end_offset], chunk.text);
            assert!(chunk.text.len() <= MAX_CHUNK_TEXT_BYTES);
            assert!(serde_json::to_vec(&chunk.text).unwrap().len() < 256 * 1024);
            if index > 0 {
                assert_eq!(chunks[index - 1].end_offset, chunk.start_offset);
            }
        }
    }

    #[test]
    fn pre_heading_nested_and_repeated_headings_keep_revision_local_paths() {
        let body = "lead\n\n# Plan\na\n\n## Do\nb\n# Plan\nc\n";
        let chunks = markdown(body);
        source_round_trip(body, &chunks);
        assert_eq!(
            chunks.iter().map(|c| c.block_kind).collect::<Vec<_>>(),
            [
                "paragraph",
                "heading",
                "paragraph",
                "heading",
                "paragraph",
                "heading",
                "paragraph"
            ]
        );
        assert!(chunks[0].heading_path.is_empty());
        assert_eq!(chunks[0].text, "lead\n\n");
        assert_eq!(
            chunks[4]
                .heading_path
                .iter()
                .map(|h| h.title.as_str())
                .collect::<Vec<_>>(),
            ["Plan", "Do"]
        );
        assert_eq!(chunks[6].heading_path.len(), 1);
        assert_ne!(
            chunks[1].heading_path[0].block_index,
            chunks[5].heading_path[0].block_index
        );
    }

    #[test]
    fn unicode_crlf_fences_and_leading_whitespace_are_raw_bytes() {
        let body = "\n\n# Café\r\n\r\n```rust\r\n# not a heading\r\n```\r\n\r\n😀 end\r\n";
        let chunks = markdown(body);
        source_round_trip(body, &chunks);
        assert_eq!(chunks[0].block_kind, "interstitial");
        assert_eq!(chunks[1].block_kind, "heading");
        assert_eq!(chunks[2].block_kind, "code");
        assert_eq!(chunks[3].block_kind, "paragraph");
        assert!(chunks[2].text.contains("# not a heading"));
        assert_eq!(chunks[3].heading_path[0].title, "Café");
    }

    #[test]
    fn oversized_block_is_losslessly_chunked_below_json_cell_cap() {
        let body = format!("# Big\n\n```\n{}\n```\n", "\u{0001}😀".repeat(65_000));
        let chunks = markdown(&body);
        source_round_trip(&body, &chunks);
        let code: Vec<_> = chunks.iter().filter(|c| c.block_kind == "code").collect();
        assert!(code.len() > 1);
        assert!(code.iter().all(|chunk| chunk.chunk_count == code.len()));
        assert_eq!(
            code.iter()
                .map(|chunk| chunk.chunk_index)
                .collect::<Vec<_>>(),
            (0..code.len()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn worst_case_control_escaping_and_long_headings_stay_bounded() {
        let controls = "\u{0000}".repeat(MAX_CHUNK_TEXT_BYTES);
        let opaque = extract_body_blocks(Some(&controls), BodyFormat::Opaque).unwrap();
        source_round_trip(&controls, &opaque);
        assert_eq!(opaque.len(), 1);
        assert_eq!(
            serde_json::to_vec(&opaque[0].text).unwrap().len(),
            6 * MAX_CHUNK_TEXT_BYTES + 2
        );

        let title = "é".repeat(MAX_HEADING_TITLE_CHARS + 10);
        let body = format!("# {title}\n\nunder it\n");
        let chunks = markdown(&body);
        source_round_trip(&body, &chunks);
        assert_eq!(
            chunks[1].heading_path[0].title.chars().count(),
            MAX_HEADING_TITLE_CHARS
        );
        assert!(chunks[1].heading_path[0].title_truncated);
        assert_eq!(
            chunks[1].heading_path[0].block_index,
            chunks[0].heading_path[0].block_index
        );
    }

    #[test]
    fn image_alt_text_and_reference_labels_survive_heading_rendering() {
        let body = "# ![Status](status.svg) and ![Ready][r]\n\n[r]: ready.svg\n";
        let chunks = markdown(body);
        source_round_trip(body, &chunks);
        assert_eq!(chunks[0].heading_path[0].title, "Status and Ready");
        assert!(!chunks[0].heading_path[0].title_truncated);
    }

    #[test]
    fn heading_breaks_render_as_separators() {
        use markdown::{
            mdast::{Break, Text},
            unist::Position,
        };
        let children = vec![
            Node::Text(Text {
                value: "first".into(),
                position: None,
            }),
            Node::Break(Break {
                position: Some(Position::new(1, 6, 5, 2, 1, 7)),
            }),
            Node::Text(Text {
                value: "second".into(),
                position: None,
            }),
        ];
        assert_eq!(heading_title(&children), ("first second".into(), false));
    }

    #[test]
    fn opaque_body_never_invents_markdown_sections() {
        let body = "{\"body\":\"# pretend heading\\n- [ ] task\"}";
        let chunks = extract_body_blocks(Some(body), BodyFormat::Opaque).unwrap();
        source_round_trip(body, &chunks);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].block_kind, "opaque");
        assert!(chunks[0].heading_path.is_empty());
        assert!(extract_body_blocks(None, BodyFormat::Markdown)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn projection_admission_caps_body_bytes_and_chunk_count() {
        let over_bytes = "x".repeat(MAX_PROJECTED_BODY_BYTES + 1);
        let error =
            extract_projectable_body_blocks(Some(&over_bytes), BodyFormat::Opaque).unwrap_err();
        assert!(error.message.contains("16777216-byte"));
        let many_blocks = "# h\n\nx\n\n".repeat(MAX_PROJECTED_CHUNKS);
        assert!(many_blocks.len() < MAX_PROJECTED_BODY_BYTES);
        let error =
            extract_projectable_body_blocks(Some(&many_blocks), BodyFormat::Markdown).unwrap_err();
        assert!(error.message.contains("4096-chunk"));
        let bounded = "z".repeat(MAX_CHUNK_TEXT_BYTES * 2 + 1);
        let chunks = extract_projectable_body_blocks(Some(&bounded), BodyFormat::Opaque).unwrap();
        assert_eq!(chunks.len(), 3);
        source_round_trip(&bounded, &chunks);
    }

    #[test]
    fn malformed_positions_refuse_and_unclosed_fence_stays_code() {
        use markdown::{mdast::Paragraph, unist::Position};
        let missing = Node::Paragraph(Paragraph {
            children: vec![],
            position: None,
        });
        assert!(validate_starts(&[missing], "x").is_err());
        let bad = Node::Paragraph(Paragraph {
            children: vec![],
            position: Some(Position::new(1, 1, 0, 1, 9, 9)),
        });
        assert!(validate_starts(&[bad], "x").is_err());
        let body = "```\n# still code";
        let chunks = markdown(body);
        source_round_trip(body, &chunks);
        assert_eq!(chunks[0].block_kind, "code");
    }
}
