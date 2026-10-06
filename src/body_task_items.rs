//! Pure GFM task-list extraction over record-body text (E3 M3 increment 1).
//!
//! No storage, projection, SQL surface, or migration lives here: this module
//! turns body text into a [`Vec<TaskItem>`] using the already-vendored
//! `markdown = "=1.0.0"` crate's `mdast`. The projector (later increment)
//! will persist these rows; the W3 query will filter them.
//!
//! Contract notes, all confirmed against `markdown-1.0.0` behaviour:
//! - `ListItem.checked` is `Some(false)` for `[ ]`, `Some(true)` for
//!   `[x]`/`[X]`, and `None` for plain items or a bare `- [ ]` with no
//!   trailing content (GFM requires content after the check). Only `Some`
//!   items are emitted, so a bare checkbox-only `- [ ]` line with no item
//!   text yields no row. That exclusion is **decided W3 acceptance semantics**
//!   (Richard, 27 Sep 2026, recorded in E4 M1 `dbb9bc1`: bare checkbox-only
//!   lines do not count), and the parser behaviour matches it by construction
//!   rather than by silent assumption — see
//!   `bare_checkbox_only_lines_are_excluded`.
//! - GFM task support is **not** on by default (`gfm_task_list_item`
//!   defaults to false), so the options are fixed to [`Constructs::gfm()`]
//!   inside this module. Callers cannot accidentally get CommonMark-only
//!   parsing (which would silently yield zero rows).
//! - Fenced code (``` or ~~~, closed or unclosed), indented code, and HTML
//!   blocks parse as `Code`/`Html`, never `ListItem`: fence-only bodies
//!   structurally yield zero rows.
//! - `> - [ ]` still parses as a `ListItem` inside a `Blockquote` ancestor,
//!   so quote exclusion is a flag ([`TaskItem::in_quote`]), not absence.
//! - mdast keeps `List.ordered` but drops the unordered marker char, so the
//!   `-`/`*`/`+` marker is recovered from the source bytes at the item's
//!   start offset (positions always land at or before the marker; leading
//!   spaces/tabs are skipped). Ordered items report [`TaskMarker::Ordered`]
//!   from the parent `List` flag, never from byte-sniffing.
//! - Failure is fallible, never silent: [`extract_task_items`] returns
//!   [`Result`], and a `to_mdast` error propagates as [`ExtractError`] so a
//!   projector or migration must refuse rather than persist "zero tasks"
//!   for a body it never parsed. (With MDX constructs off, `to_mdast`
//!   documents "never errors with normal markdown", and no erroring input
//!   was found by probing — NUL bytes, lone CR, 5000-deep brackets all
//!   parse — so the `Err` branch is currently unreachable in practice. The
//!   `Result` exists so that unreachability stays an observation, not a
//!   load-bearing assumption: if options or the crate ever change, the
//!   projector fails closed instead of silently erasing task rows and
//!   corrupting W3's target set while appearing successful.)
//! - All offsets are **byte** offsets into the original `&str`; slicing
//!   `body[start_offset..end_offset]` always lands on char boundaries for
//!   emitted items (positions come from the parser's own byte model).

use markdown::{mdast::Node, to_mdast, Constructs, ParseOptions};

/// The list marker that introduced a task item.
///
/// Strict E4 M1 W3 admits only [`TaskMarker::Dash`], [`TaskMarker::Star`],
/// and [`TaskMarker::Plus`]; [`TaskMarker::Ordered`] items are representable
/// but must be filtered out of the W3 target set (ordered-only is a negative
/// W3 fixture). [`TaskMarker::Unknown`] is never emitted by
/// [`extract_task_items`] — a checked item with a missing position or an
/// unrecoverable unordered marker is an [`ExtractError`], not an `Unknown`
/// row, so W3 can never silently omit a real unchecked item if mdast
/// positions or recovery ever change. The variant is retained so matches
/// over [`TaskMarker`] stay exhaustive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskMarker {
    Dash,
    Star,
    Plus,
    Ordered,
    Unknown,
}

impl TaskMarker {
    /// Storage spelling for the `body_task_items.marker` CHECK
    /// (`'-'`, `'*'`, `'+'`, `'ordered'`). `Unknown` has no spelling — it is
    /// never emitted by [`extract_task_items`], and every projection path
    /// must refuse it rather than persist a row no query can interpret.
    pub fn as_str(&self) -> Option<&'static str> {
        match self {
            TaskMarker::Dash => Some("-"),
            TaskMarker::Star => Some("*"),
            TaskMarker::Plus => Some("+"),
            TaskMarker::Ordered => Some("ordered"),
            TaskMarker::Unknown => None,
        }
    }
}

/// One GFM task-list item found in body text, in document order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskItem {
    /// Zero-based document order among emitted task items.
    pub index: usize,
    /// The marker kind; see [`TaskMarker`] for the W3 rule.
    pub marker: TaskMarker,
    /// `false` for `[ ]`, `true` for `[x]`/`[X]`.
    pub checked: bool,
    /// True when any ancestor node is a blockquote (`> - [ ]`, at any depth
    /// or spacing). Quote-only bodies yield rows with `in_quote == true`.
    pub in_quote: bool,
    /// Byte offsets of the item from its mdast position.
    pub start_offset: usize,
    /// Byte offsets of the item from its mdast position.
    pub end_offset: usize,
}

impl TaskItem {
    /// Strict W3 candidate: unchecked, unquoted, unordered `-`/`*`/`+`.
    pub fn is_w3_candidate(&self) -> bool {
        !self.checked
            && !self.in_quote
            && matches!(
                self.marker,
                TaskMarker::Dash | TaskMarker::Star | TaskMarker::Plus
            )
    }
}

/// Parse failure for [`extract_task_items`]. Carries the underlying
/// `markdown` message verbatim; the projector must treat it as "body
/// unparsed — refuse", never as "zero tasks".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractError {
    /// The `markdown::message::Message` display string.
    pub message: String,
}

impl ExtractError {
    fn from_message(message: markdown::message::Message) -> Self {
        Self {
            message: message.to_string(),
        }
    }

    /// A checked task item arrived without an mdast position, so neither its
    /// marker nor its offsets are recoverable.
    fn missing_position() -> Self {
        Self {
            message: "task list item has no source position; refusing to guess its marker".into(),
        }
    }

    /// The bytes at `offset` hold no `-`/`*`/`+` marker for an unordered
    /// item, so emitting it as `Unknown` would silently drop a real task
    /// from W3's target set.
    fn unrecoverable_marker(offset: usize) -> Self {
        Self {
            message: format!(
                "task list item at byte offset {offset} has no recoverable marker; refusing Unknown"
            ),
        }
    }
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "body task extraction failed: {}", self.message)
    }
}

impl std::error::Error for ExtractError {}

/// Extract task items from body text.
///
/// Returns `Err` when the body does not parse: callers must propagate the
/// failure (fail closed), never substitute an empty task set. `Ok` with an
/// empty vec means "parsed, and no task row of any kind" — fence-only,
/// inline-only, empty, and bare checkbox-only bodies land here. Quote-only
/// and checked-only bodies instead emit rows with `in_quote == true` or
/// `checked == true`, which [`TaskItem::is_w3_candidate`] filters out: they
/// are non-candidate rows, not an empty vec. See the module docs.
pub fn extract_task_items(body: &str) -> Result<Vec<TaskItem>, ExtractError> {
    let options = ParseOptions {
        constructs: Constructs::gfm(),
        ..ParseOptions::default()
    };
    let root = to_mdast(body, &options).map_err(ExtractError::from_message)?;
    let mut out = Vec::new();
    walk(&root, body, false, &mut out)?;
    Ok(out)
}

/// `None` (SQL `NULL` body) carries no tasks: `Ok` with an empty vec, with
/// no parse involved and therefore no failure mode.
pub fn extract_task_items_opt(body: Option<&str>) -> Result<Vec<TaskItem>, ExtractError> {
    body.map(extract_task_items).unwrap_or(Ok(Vec::new()))
}

fn walk(
    node: &Node,
    source: &str,
    in_quote: bool,
    out: &mut Vec<TaskItem>,
) -> Result<(), ExtractError> {
    match node {
        Node::Root(root) => {
            for child in &root.children {
                walk(child, source, in_quote, out)?;
            }
        }
        Node::Blockquote(quote) => {
            for child in &quote.children {
                walk(child, source, true, out)?;
            }
        }
        Node::List(list) => {
            for child in &list.children {
                walk_list_item(child, source, in_quote, list.ordered, out)?;
            }
        }
        _ => {
            // Code/Html/paragraphs cannot contain task items; nested container
            // children of a ListItem are visited via walk_list_item below.
            if let Some(children) = node.children() {
                // Blockquote handled above; any other container with children
                // (e.g. a ListItem reached directly) keeps the quote flag.
                for child in children {
                    walk(child, source, in_quote, out)?;
                }
            }
        }
    }
    Ok(())
}

fn walk_list_item(
    node: &Node,
    source: &str,
    in_quote: bool,
    parent_ordered: bool,
    out: &mut Vec<TaskItem>,
) -> Result<(), ExtractError> {
    let Node::ListItem(item) = node else {
        return walk(node, source, in_quote, out);
    };
    if let Some(checked) = item.checked {
        // Fail closed: a checked item without a position, or with bytes that
        // hold no unordered marker, is an error — never an `Unknown` row
        // that W3 would silently filter out.
        let Some(position) = &item.position else {
            return Err(ExtractError::missing_position());
        };
        let marker = recover_marker(source, position.start.offset, parent_ordered);
        if marker == TaskMarker::Unknown {
            return Err(ExtractError::unrecoverable_marker(position.start.offset));
        }
        out.push(TaskItem {
            index: out.len(),
            marker,
            checked,
            in_quote,
            start_offset: position.start.offset,
            end_offset: position.end.offset,
        });
    }
    // Nested lists live among the item's children; a blockquote child sets
    // the flag only for its own subtree, never for this item (decided above).
    for child in &item.children {
        walk(child, source, in_quote, out)?;
    }
    Ok(())
}

/// Recover the unordered marker byte at or after `offset` (leading spaces
/// and tabs skipped). Ordered-ness always comes from the parent `List`.
fn recover_marker(source: &str, offset: usize, parent_ordered: bool) -> TaskMarker {
    if parent_ordered {
        return TaskMarker::Ordered;
    }
    let mut bytes = source.as_bytes().get(offset..).unwrap_or_default().iter();
    for byte in bytes.by_ref() {
        match byte {
            b' ' | b'\t' => continue,
            b'-' => return TaskMarker::Dash,
            b'*' => return TaskMarker::Star,
            b'+' => return TaskMarker::Plus,
            _ => break,
        }
    }
    TaskMarker::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test bodies must parse: an `Err` here is a test failure, mirroring
    /// the projector contract (fail closed, never substitute zero tasks).
    fn extract(body: &str) -> Vec<TaskItem> {
        extract_task_items(body).expect("test body must parse")
    }

    fn w3_count(body: &str) -> usize {
        extract(body)
            .iter()
            .filter(|item| item.is_w3_candidate())
            .count()
    }

    #[test]
    fn real_dash_star_plus_are_w3_candidates_with_markers() {
        for (body, marker) in [
            ("- [ ] real\n", TaskMarker::Dash),
            ("* [ ] real\n", TaskMarker::Star),
            ("+ [ ] real\n", TaskMarker::Plus),
        ] {
            let items = extract(body);
            assert_eq!(items.len(), 1, "{body:?}");
            assert_eq!(items[0].marker, marker, "{body:?}");
            assert!(!items[0].checked && !items[0].in_quote, "{body:?}");
            assert!(items[0].is_w3_candidate(), "{body:?}");
        }
    }

    #[test]
    fn ordered_only_is_not_a_w3_candidate() {
        for body in ["1. [ ] o-task\n", "1) [ ] o-task\n"] {
            let items = extract(body);
            assert_eq!(items.len(), 1, "{body:?}");
            assert_eq!(items[0].marker, TaskMarker::Ordered, "{body:?}");
            assert!(!items[0].is_w3_candidate(), "{body:?}");
            assert_eq!(w3_count(body), 0, "{body:?}");
        }
    }

    #[test]
    fn mixed_real_plus_fence_plus_quote_keeps_one_candidate() {
        let body = "- [ ] real\n```\n- [ ] fake\n```\n> - [ ] quoted\n";
        let items = extract(body);
        assert_eq!(items.len(), 2, "{items:?}");
        assert!(items[0].is_w3_candidate(), "{items:?}");
        assert!(
            items[1].in_quote && !items[1].is_w3_candidate(),
            "{items:?}"
        );
        assert_eq!(w3_count(body), 1);
    }

    #[test]
    fn fence_only_quote_only_inline_only_yield_no_candidate() {
        assert!(extract("```\n- [ ] fake\n```\n").is_empty());
        let quoted = extract("> - [ ] only\n");
        assert_eq!(quoted.len(), 1);
        assert!(quoted[0].in_quote && !quoted[0].is_w3_candidate());
        assert!(extract("see `- [ ]` here\n").is_empty());
    }

    #[test]
    fn tilde_unclosed_and_indented_code_yield_no_rows() {
        assert!(extract("~~~\n- [ ] fake\n~~~\n").is_empty());
        assert!(extract("```\n- [ ] fake\n").is_empty());
        assert!(extract("```rust\n- [ ] fake\n```\n").is_empty());
        assert!(extract("    - [ ] fake\n").is_empty());
    }

    #[test]
    fn nested_tasks_both_count_at_any_depth() {
        let items = extract("- [ ] outer\n  - [ ] inner\n");
        assert_eq!(items.len(), 2, "{items:?}");
        for item in &items {
            assert_eq!(item.marker, TaskMarker::Dash, "{item:?}");
            assert!(item.is_w3_candidate(), "{item:?}");
        }
        assert_eq!(items[0].index, 0);
        assert_eq!(items[1].index, 1);
    }

    #[test]
    fn spaced_quote_is_still_quoted() {
        let items = extract("  > - [ ] q\n");
        assert_eq!(items.len(), 1, "{items:?}");
        assert!(items[0].in_quote, "{items:?}");
        assert!(!items[0].is_w3_candidate(), "{items:?}");
    }

    #[test]
    fn checked_only_has_no_w3_candidate() {
        let items = extract("- [x] done\n- [X] done2\n");
        assert_eq!(items.len(), 2, "{items:?}");
        assert!(items.iter().all(|item| item.checked), "{items:?}");
        assert_eq!(w3_count("- [x] done\n- [X] done2\n"), 0);
    }

    #[test]
    fn bare_checkbox_only_lines_are_excluded() {
        // Decided W3 acceptance semantics (Richard, 27 Sep 2026, recorded
        // in E4 M1 dbb9bc1): a bare checkbox-only line with no item text
        // does not count. GFM agrees —
        // the check requires trailing content, so these parse as plain
        // (`checked == None`) list items and yield no rows.
        for body in ["- [ ]\n", "- [X]\n", "* [ ]\n", "+ [ ]   \n", "1. [ ]\n"] {
            assert!(extract(body).is_empty(), "{body:?}");
            assert_eq!(w3_count(body), 0, "{body:?}");
        }
    }

    #[test]
    fn empty_none_yield_no_rows() {
        // GFM requires content after the check tested above; these never
        // reach the parser as candidate content at all.
        assert!(extract("").is_empty());
        assert!(extract("just text\n").is_empty());
        assert!(extract_task_items_opt(None)
            .expect("None never fails")
            .is_empty());
        assert!(extract_task_items_opt(Some(""))
            .expect("empty parses")
            .is_empty());
    }

    #[test]
    fn indented_unordered_markers_recover() {
        let items = extract("  * [ ] x\n");
        assert_eq!(items.len(), 1, "{items:?}");
        assert_eq!(items[0].marker, TaskMarker::Star, "{items:?}");
        assert!(items[0].is_w3_candidate(), "{items:?}");
    }

    #[test]
    fn quoted_markers_recover_with_quote_flag() {
        // mdast positions land exactly on the marker byte even under one or
        // more `>` prefixes, so the relation's marker promise holds for
        // quoted rows too; W3 still filters them via `in_quote`.
        for (body, marker) in [
            ("> - [ ] q\n", TaskMarker::Dash),
            ("> * [ ] q\n", TaskMarker::Star),
            ("> + [ ] q\n", TaskMarker::Plus),
            (">> - [ ] q\n", TaskMarker::Dash),
            ("> 2) [ ] q\n", TaskMarker::Ordered),
        ] {
            let items = extract(body);
            assert_eq!(items.len(), 1, "{body:?}");
            assert_eq!(items[0].marker, marker, "{body:?}");
            assert!(items[0].in_quote, "{body:?}");
            assert!(!items[0].is_w3_candidate(), "{body:?}");
            // The start offset slices the marker byte itself, even under
            // `>` prefixes: `-`/`*`/`+` verbatim, a digit for ordered.
            let byte = body.as_bytes()[items[0].start_offset];
            match marker {
                TaskMarker::Dash => assert_eq!(byte, b'-', "{body:?}"),
                TaskMarker::Star => assert_eq!(byte, b'*', "{body:?}"),
                TaskMarker::Plus => assert_eq!(byte, b'+', "{body:?}"),
                TaskMarker::Ordered => assert!(byte.is_ascii_digit(), "{body:?}"),
                TaskMarker::Unknown => panic!("quoted marker must recover, {body:?}"),
            }
        }
    }

    #[test]
    fn offsets_are_bytes_and_slice_marker_and_item() {
        // Multibyte text before the item: offsets must be byte offsets that
        // slice the intended marker and item, not char indices.
        let body = "héllo wörld ✓\n- [ ] tâsk ✓\n";
        let items = extract(body);
        assert_eq!(items.len(), 1, "{items:?}");
        let item = &items[0];
        assert_eq!(&body[item.start_offset..item.start_offset + 1], "-");
        let slice = &body[item.start_offset..item.end_offset];
        assert_eq!(slice, "- [ ] tâsk ✓", "{slice:?}");
        assert_eq!(item.marker, TaskMarker::Dash);

        // CRLF: offsets remain byte-exact slices through \r\n boundaries.
        let crlf = "héllo ✓\r\n* [ ] tâsk ✓\r\n";
        let items = extract(crlf);
        assert_eq!(items.len(), 1, "{items:?}");
        let item = &items[0];
        assert_eq!(&crlf[item.start_offset..item.start_offset + 1], "*");
        assert!(
            crlf[item.start_offset..item.end_offset].contains("[ ]"),
            "{item:?}"
        );
        assert_eq!(item.marker, TaskMarker::Star);
        assert!(item.is_w3_candidate(), "{item:?}");
    }

    #[test]
    fn adversarial_bodies_parse_without_silent_empty() {
        // NUL bytes, lone CR, and 5000-deep brackets all parse (possibly to
        // zero rows); the point is `Ok`, never a swallowed `Err` masquerading
        // as "no tasks". A projector seeing `Ok(vec![])` knows the body was
        // actually parsed.
        for body in ["a\0b\n- [ ] x\n", "- [ ] a\rb\n", &"[".repeat(5000)] {
            let result = extract_task_items(body);
            assert!(result.is_ok(), "{body:?}");
        }
        assert_eq!(extract("a\0b\n- [ ] x\n").len(), 1);
    }

    #[test]
    fn parse_error_maps_to_extract_error() {
        // The `Err` branch is unreachable via the fixed GFM options (see
        // module docs), so this pins the mapping, not a live parse failure:
        // a future failure must refuse with its message, not erase rows.
        let message = markdown::message::Message {
            place: None,
            reason: "boom".into(),
            rule_id: Box::new("test".to_owned()),
            source: Box::new("test".to_owned()),
        };
        let error = ExtractError::from_message(message);
        assert!(error.to_string().contains("boom"), "{error:?}");
    }

    #[test]
    fn missing_position_or_unrecoverable_marker_is_err_not_unknown() {
        use markdown::mdast::ListItem;
        use markdown::unist::Position;

        // Checked item, no position: refuse, emit nothing.
        let node = Node::ListItem(ListItem {
            children: vec![],
            position: None,
            spread: false,
            checked: Some(false),
        });
        let mut out = Vec::new();
        let error = walk_list_item(&node, "- [ ] x\n", false, false, &mut out)
            .expect_err("missing position must fail closed");
        assert!(
            error.to_string().contains("no source position"),
            "{error:?}"
        );
        assert!(out.is_empty());

        // Position lands inside "[ ]" where no marker byte exists: refuse.
        let body = "- [ ] x\n";
        let node = Node::ListItem(ListItem {
            children: vec![],
            position: Some(Position::new(1, 3, 2, 1, 8, 7)),
            spread: false,
            checked: Some(false),
        });
        let mut out = Vec::new();
        let error = walk_list_item(&node, body, false, false, &mut out)
            .expect_err("unrecoverable marker must fail closed");
        assert!(
            error.to_string().contains("no recoverable marker"),
            "{error:?}"
        );
        assert!(out.is_empty());
    }

    #[test]
    fn extractor_never_emits_unknown_markers() {
        // Across the whole fixture battery (real, ordered, quoted, nested,
        // multibyte, CRLF), every emitted row carries a concrete marker, so
        // no W3 row can ever be filtered via the `Unknown` path.
        let bodies = [
            "- [ ] a\n",
            "* [ ] a\n",
            "+ [ ] a\n",
            "1. [ ] a\n",
            "1) [ ] a\n",
            "> - [ ] a\n",
            "> * [ ] a\n",
            ">> + [ ] a\n",
            "> 2) [ ] a\n",
            "- [ ] outer\n  - [ ] inner\n",
            "> - a\n>   - [ ] deep\n",
            "- [x] done\n",
            "  * [ ] x\n",
            "héllo ✓\n- [ ] tâsk ✓\n",
            "héllo ✓\r\n* [ ] tâsk ✓\r\n",
            "- [ ] real\n```\n- [ ] fake\n```\n> - [ ] q\n",
        ];
        for body in bodies {
            for item in extract(body) {
                assert_ne!(item.marker, TaskMarker::Unknown, "{body:?} {item:?}");
            }
        }
    }
}
