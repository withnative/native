//! Tier-one author CSS: validate, rewrite and re-serialise an author
//! stylesheet.
//!
//! This module is deliberately self-contained. It hand-implements the CSS
//! Syntax Level 3 tokenizer and a rule/declaration parser, because the crate
//! graph carries no CSS parser and must not gain one (`Cargo.lock` is hashed
//! into the compiled-graph cache key and the published module release digest).
//!
//! The load-bearing security property is **parse and re-serialise**: every byte
//! of the returned stylesheet is emitted from this module's own token tree,
//! never concatenated from author bytes. Author text therefore cannot close the
//! generated `@scope` block and reopen a never-matching one, which is how a
//! naive string wrapper was escaped previously.
//!
//! Two rewrites are mandatory and are performed on the parsed tree:
//!
//! 1. **Class prefixing.** Every class selector `.foo` becomes
//!    `.{class_prefix}foo`, so the host's own unscoped stylesheet cannot style
//!    an author element that happens to claim a host class name.
//! 2. **Scope wrapping.** The validated rules are emitted inside
//!    `@scope ({scope_root}) to ({scope_limit}) { ... }`.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Identifier reported in failure details for this validator.
pub const RUNTIME_ID: &str = "native.css.v1";

/// Maximum accepted author source, in UTF-8 bytes.
///
/// A later lane moves this into the artifact descriptor; it is named here so
/// that move is a reference change rather than a rediscovery.
pub const MAX_SOURCE_BYTES: usize = 64 * 1024;

/// Maximum number of rules (qualified rules plus at-rules, at any depth).
pub const MAX_RULES: usize = 1024;

/// Maximum block nesting depth, enforced **during parsing**.
///
/// The parser is recursive descent: `parse_nodes` and `parse_qualified_rule`
/// call each other once per nesting level. `MAX_RULES` cannot bound that,
/// because it is counted by the post-parse `Walk` — by then the recursion has
/// already happened. A source of `"a{"` repeated overflows the stack and
/// aborts the process (`SIGABRT`), which `catch_unwind` cannot contain; at a
/// 2 MiB worker stack a 16 KiB source is enough, well under `MAX_SOURCE_BYTES`.
///
/// Capping at parse time is what makes `emit`, `Walk::visit_all` and the
/// recursive `Drop` of `Node` safe as well: none of them can be handed a tree
/// deeper than this, because no such tree can be constructed. Real stylesheets
/// nest a handful of levels, so this is generous.
pub const MAX_NESTING_DEPTH: usize = 64;

// ---------------------------------------------------------------------------
// Failure
// ---------------------------------------------------------------------------

/// Failure shape mirrored from `crate::mdx::Failure`: a stable `code`, a public
/// `message`, and a details object carrying `phase`, `runtime` and the named
/// `rule` that rejected the stylesheet.
#[derive(Clone, Debug)]
pub struct Failure {
    pub code: &'static str,
    pub message: String,
    pub details: Value,
}

impl Failure {
    pub fn new(code: &'static str, phase: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: json!({ "phase": phase, "runtime": RUNTIME_ID, "adapter_revision": 1 }),
        }
    }

    pub fn detail(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.details
            .as_object_mut()
            .expect("failure details are an object")
            .insert(key.into(), value.into());
        self
    }

    /// The named rule that rejected the stylesheet, if any.
    pub fn rule(&self) -> Option<&str> {
        self.details.get("rule").and_then(Value::as_str)
    }
}

fn policy(rule: &'static str, message: impl Into<String>) -> Failure {
    Failure::new("css_policy_violation", "policy", message).detail("rule", rule)
}

fn syntax(rule: &'static str, message: impl Into<String>) -> Failure {
    Failure::new("css_parse_failed", "parse", message).detail("rule", rule)
}

// ---------------------------------------------------------------------------
// Public result
// ---------------------------------------------------------------------------

/// A non-rejecting observation about the stylesheet. Novelty is made visible
/// rather than silently allowed or rejected outright.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Flag {
    /// Named rule that produced the observation.
    pub rule: &'static str,
    /// The at-rule name, property name, function name or selector the
    /// observation is about.
    pub name: String,
}

/// A validated, rewritten and re-serialised stylesheet.
#[derive(Clone, Debug)]
pub struct StyleSheet {
    /// The emitted CSS, wrapped in the requested `@scope` block.
    pub css: String,
    /// Hex SHA-256 of `css`.
    pub sha256: String,
    /// Rules counted in the author source (qualified rules plus at-rules, all
    /// depths). Excludes the generated `@scope` wrapper.
    pub rules: usize,
    /// Sorted, de-duplicated observations.
    pub flags: Vec<Flag>,
}

impl StyleSheet {
    /// Heap this sheet holds, for the parsed-source cache's byte budget.
    ///
    /// The emitted CSS dominates, but a sheet may carry up to one flag per
    /// distinct unknown at-rule, property or function, and one per id
    /// selector, each owning a name.
    /// `sha256` is a fixed 64 bytes and `rules` is a `usize`, so neither can
    /// grow with the source; the two `Vec`/`String` allocations that can are
    /// the ones counted here.
    pub fn cached_bytes(&self) -> usize {
        self.flags
            .iter()
            .fold(self.css.len(), |total, flag| {
                total
                    .saturating_add(flag.name.len())
                    .saturating_add(flag.rule.len())
            })
            .saturating_add(self.sha256.len())
    }
}

// ---------------------------------------------------------------------------
// Policy tables
// ---------------------------------------------------------------------------

/// At-rules that register a globally-visible name. They are rejected at any
/// nesting depth: nesting them inside `@media`/`@supports`/`@container`/
/// `@layer` does not scope the name they define, so a contained one is still a
/// full escape.
const FORBIDDEN_AT_RULES: &[&str] = &[
    "keyframes",
    "font-face",
    "property",
    "counter-style",
    "font-palette-values",
    "font-feature-values",
    "color-profile",
    "position-try",
    "view-transition",
    "page",
    "namespace",
];

/// At-rules understood by this validator. Anything else is flagged, not
/// rejected.
const KNOWN_AT_RULES: &[&str] = &[
    "media",
    "supports",
    "container",
    "layer",
    "scope",
    "starting-style",
];

/// Vendor prefixes stripped before the forbidden-at-rule comparison, so
/// `@-webkit-keyframes` cannot slip past the ban.
const VENDOR_PREFIXES: &[&str] = &["-webkit-", "-moz-", "-ms-", "-o-", "-khtml-"];

/// Value functions that take a URL as a bare string argument, which would
/// bypass the `url()` check entirely. Rejected rather than flagged: a string
/// URL inside `image-set()` is live network egress with no `url()` token to
/// inspect.
///
/// Entries are matched against both the function name and its vendor-stripped
/// form, so `image-rect` covers `-moz-image-rect` and `image-set` covers
/// `-webkit-image-set`.
///
/// `image()` and `image-rect()` are here on shape, not on observed behaviour.
/// Neither is implemented in Chromium today, so neither fetches anything — but
/// both take a bare string URL, which is the entire reason `image-set()` and
/// `src()` are rejected, and a denylist assembled from what fetches today is a
/// denylist that goes stale the week a browser ships one of them.
const FORBIDDEN_URL_FUNCTIONS: &[&str] = &[
    "image-set",
    "-webkit-image-set",
    "src",
    "image",
    "image-rect",
];

/// `element()` paints an arbitrary same-document element as an image (Firefox
/// today, via `-moz-element()`). It is not a URL function — it fetches nothing
/// — so it is refused separately and under its own rule name.
///
/// It is rejected rather than flagged because it reads *across* the artifact
/// boundary, in the one namespace this module deliberately declines to rewrite:
/// its argument is an id selector, and ids are flagged rather than prefixed
/// because the id rewrite belongs to the HTML lane. Host chrome painted inside
/// the artifact is the same disclosure as a screenshot of it, and no author use
/// inside a `@scope`d artifact needs it.
const FORBIDDEN_ELEMENT_FUNCTIONS: &[&str] = &["element"];

/// Functions understood by this validator. Anything else is flagged, not
/// rejected — the same treatment `KNOWN_AT_RULES` and `KNOWN_PROPERTIES` give
/// novelty, and the symmetry is the point: an unknown function used to produce
/// nothing at all.
///
/// Both value functions and functional pseudo-classes are here, because both
/// arrive as `Function` tokens: `rgb(` from a declaration value and `not(` from
/// a selector are the same token to this module.
///
/// Compared against the full lowercased name, so a vendor-prefixed spelling of
/// a known function is still flagged. That matches at-rules and properties,
/// where `-webkit-transform` is flagged too: the prefix is itself the novelty.
const KNOWN_FUNCTIONS: &[&str] = &[
    "abs",
    "acos",
    "anchor",
    "anchor-size",
    "asin",
    "atan",
    "atan2",
    "attr",
    "blur",
    "brightness",
    "calc",
    "circle",
    "clamp",
    "color",
    "color-mix",
    "conic-gradient",
    "contrast",
    "cos",
    "counter",
    "counters",
    "cross-fade",
    "cubic-bezier",
    "dir",
    "drop-shadow",
    "ellipse",
    "env",
    "exp",
    "fit-content",
    "grayscale",
    "has",
    "host",
    "host-context",
    "hsl",
    "hsla",
    "hue-rotate",
    "hwb",
    "hypot",
    "inset",
    "invert",
    "is",
    "lab",
    "lang",
    "lch",
    "light-dark",
    "linear",
    "linear-gradient",
    "log",
    "matrix",
    "matrix3d",
    "max",
    "min",
    "minmax",
    "mod",
    "not",
    "nth-child",
    "nth-col",
    "nth-last-child",
    "nth-last-col",
    "nth-last-of-type",
    "nth-of-type",
    "oklab",
    "oklch",
    "opacity",
    "part",
    "path",
    "perspective",
    "polygon",
    "pow",
    "radial-gradient",
    "ray",
    "rect",
    "rem",
    "repeat",
    "repeating-conic-gradient",
    "repeating-linear-gradient",
    "repeating-radial-gradient",
    "rgb",
    "rgba",
    "rotate",
    "rotate3d",
    "rotatex",
    "rotatey",
    "rotatez",
    "round",
    "saturate",
    "scale",
    "scale3d",
    "scalex",
    "scaley",
    "scalez",
    "scroll",
    "scroll-state",
    "selector",
    "sepia",
    "shape",
    "sign",
    "sin",
    "skew",
    "skewx",
    "skewy",
    "slotted",
    "sqrt",
    "state",
    "steps",
    "style",
    "symbols",
    "tan",
    "translate",
    "translate3d",
    "translatex",
    "translatey",
    "translatez",
    "url",
    "var",
    "view",
    "where",
    "xywh",
];

const KNOWN_PROPERTIES: &[&str] = &[
    "accent-color",
    "align-content",
    "align-items",
    "align-self",
    "all",
    "animation",
    "animation-delay",
    "animation-direction",
    "animation-duration",
    "animation-fill-mode",
    "animation-iteration-count",
    "animation-name",
    "animation-play-state",
    "animation-timing-function",
    "appearance",
    "aspect-ratio",
    "backdrop-filter",
    "backface-visibility",
    "background",
    "background-attachment",
    "background-blend-mode",
    "background-clip",
    "background-color",
    "background-image",
    "background-origin",
    "background-position",
    "background-position-x",
    "background-position-y",
    "background-repeat",
    "background-size",
    "block-size",
    "border",
    "border-block",
    "border-block-end",
    "border-block-start",
    "border-bottom",
    "border-bottom-color",
    "border-bottom-left-radius",
    "border-bottom-right-radius",
    "border-bottom-style",
    "border-bottom-width",
    "border-collapse",
    "border-color",
    "border-end-end-radius",
    "border-end-start-radius",
    "border-image",
    "border-inline",
    "border-inline-end",
    "border-inline-start",
    "border-left",
    "border-left-color",
    "border-left-style",
    "border-left-width",
    "border-radius",
    "border-right",
    "border-right-color",
    "border-right-style",
    "border-right-width",
    "border-spacing",
    "border-start-end-radius",
    "border-start-start-radius",
    "border-style",
    "border-top",
    "border-top-color",
    "border-top-left-radius",
    "border-top-right-radius",
    "border-top-style",
    "border-top-width",
    "border-width",
    "bottom",
    "box-shadow",
    "box-sizing",
    "break-after",
    "break-before",
    "break-inside",
    "caption-side",
    "caret-color",
    "clear",
    "clip-path",
    "color",
    "color-scheme",
    "column-count",
    "column-fill",
    "column-gap",
    "column-rule",
    "column-rule-color",
    "column-rule-style",
    "column-rule-width",
    "column-span",
    "column-width",
    "columns",
    "contain",
    "contain-intrinsic-size",
    "container",
    "container-name",
    "container-type",
    "content",
    "counter-increment",
    "counter-reset",
    "counter-set",
    "cursor",
    "direction",
    "display",
    "empty-cells",
    "filter",
    "flex",
    "flex-basis",
    "flex-direction",
    "flex-flow",
    "flex-grow",
    "flex-shrink",
    "flex-wrap",
    "float",
    "font",
    "font-family",
    "font-feature-settings",
    "font-kerning",
    "font-optical-sizing",
    "font-size",
    "font-size-adjust",
    "font-stretch",
    "font-style",
    "font-variant",
    "font-variant-numeric",
    "font-variation-settings",
    "font-weight",
    "gap",
    "grid",
    "grid-area",
    "grid-auto-columns",
    "grid-auto-flow",
    "grid-auto-rows",
    "grid-column",
    "grid-column-end",
    "grid-column-start",
    "grid-row",
    "grid-row-end",
    "grid-row-start",
    "grid-template",
    "grid-template-areas",
    "grid-template-columns",
    "grid-template-rows",
    "height",
    "hyphens",
    "image-rendering",
    "inline-size",
    "inset",
    "inset-block",
    "inset-block-end",
    "inset-block-start",
    "inset-inline",
    "inset-inline-end",
    "inset-inline-start",
    "isolation",
    "justify-content",
    "justify-items",
    "justify-self",
    "left",
    "letter-spacing",
    "line-break",
    "line-height",
    "list-style",
    "list-style-image",
    "list-style-position",
    "list-style-type",
    "margin",
    "margin-block",
    "margin-block-end",
    "margin-block-start",
    "margin-bottom",
    "margin-inline",
    "margin-inline-end",
    "margin-inline-start",
    "margin-left",
    "margin-right",
    "margin-top",
    "mask",
    "mask-image",
    "mask-position",
    "mask-repeat",
    "mask-size",
    "max-block-size",
    "max-height",
    "max-inline-size",
    "max-width",
    "min-block-size",
    "min-height",
    "min-inline-size",
    "min-width",
    "mix-blend-mode",
    "object-fit",
    "object-position",
    "opacity",
    "order",
    "outline",
    "outline-color",
    "outline-offset",
    "outline-style",
    "outline-width",
    "overflow",
    "overflow-wrap",
    "overflow-x",
    "overflow-y",
    "overscroll-behavior",
    "padding",
    "padding-block",
    "padding-block-end",
    "padding-block-start",
    "padding-bottom",
    "padding-inline",
    "padding-inline-end",
    "padding-inline-start",
    "padding-left",
    "padding-right",
    "padding-top",
    "place-content",
    "place-items",
    "place-self",
    "pointer-events",
    "position",
    "quotes",
    "resize",
    "right",
    "rotate",
    "row-gap",
    "scale",
    "scroll-behavior",
    "scroll-margin",
    "scroll-padding",
    "scrollbar-gutter",
    "scrollbar-width",
    "shape-outside",
    "tab-size",
    "table-layout",
    "text-align",
    "text-align-last",
    "text-decoration",
    "text-decoration-color",
    "text-decoration-line",
    "text-decoration-style",
    "text-decoration-thickness",
    "text-indent",
    "text-overflow",
    "text-rendering",
    "text-shadow",
    "text-transform",
    "text-underline-offset",
    "text-wrap",
    "top",
    "touch-action",
    "transform",
    "transform-origin",
    "transform-style",
    "transition",
    "transition-delay",
    "transition-duration",
    "transition-property",
    "transition-timing-function",
    "translate",
    "unicode-bidi",
    "user-select",
    "vertical-align",
    "visibility",
    "white-space",
    "widows",
    "width",
    "will-change",
    "word-break",
    "word-spacing",
    "writing-mode",
    "z-index",
];

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Ident(String),
    /// Function name, i.e. `name(`.
    Function(String),
    AtKeyword(String),
    /// Hash value plus whether it is a valid identifier (an id selector).
    Hash(String, bool),
    Str(String),
    /// Unquoted `url(...)` value.
    Url(String),
    Delim(char),
    /// Raw numeric text (only ever digits, `.`, `e`, `E`, `+`, `-`).
    Number(String),
    /// Raw numeric text plus unit identifier.
    Dimension(String, String),
    Percentage(String),
    Whitespace,
    Colon,
    Semicolon,
    Comma,
    LBracket,
    RBracket,
    LParen,
    RParen,
    LBrace,
    RBrace,
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || (c as u32) >= 0x80
}

fn is_ident_char(c: char) -> bool {
    is_ident_start(c) || c.is_ascii_digit() || c == '-'
}

fn is_ws(c: char) -> bool {
    c == ' ' || c == '\t' || c == '\n'
}

struct Tokenizer {
    chars: Vec<char>,
    pos: usize,
}

impl Tokenizer {
    fn new(source: &str) -> Self {
        // CSS preprocessing: normalise newlines and NULLs.
        let mut chars: Vec<char> = Vec::with_capacity(source.len());
        let raw: Vec<char> = source.chars().collect();
        let mut i = 0;
        while i < raw.len() {
            match raw[i] {
                '\r' => {
                    chars.push('\n');
                    if raw.get(i + 1) == Some(&'\n') {
                        i += 1;
                    }
                }
                '\u{c}' => chars.push('\n'),
                '\0' => chars.push('\u{fffd}'),
                other => chars.push(other),
            }
            i += 1;
        }
        Self { chars, pos: 0 }
    }

    fn at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn valid_escape_at(&self, offset: usize) -> bool {
        self.at(offset) == Some('\\') && !matches!(self.at(offset + 1), Some('\n') | None)
    }

    fn would_start_ident(&self, offset: usize) -> bool {
        match self.at(offset) {
            Some('-') => match self.at(offset + 1) {
                Some('-') => true,
                Some(c) if is_ident_start(c) => true,
                _ => self.valid_escape_at(offset + 1),
            },
            Some(c) if is_ident_start(c) => true,
            Some('\\') => self.valid_escape_at(offset),
            _ => false,
        }
    }

    fn would_start_number(&self, offset: usize) -> bool {
        match self.at(offset) {
            Some('+') | Some('-') => match self.at(offset + 1) {
                Some(c) if c.is_ascii_digit() => true,
                Some('.') => matches!(self.at(offset + 2), Some(c) if c.is_ascii_digit()),
                _ => false,
            },
            Some('.') => matches!(self.at(offset + 1), Some(c) if c.is_ascii_digit()),
            Some(c) => c.is_ascii_digit(),
            None => false,
        }
    }

    /// Consumes an escape sequence, the leading `\` already consumed.
    fn consume_escape(&mut self) -> char {
        let Some(first) = self.at(0) else {
            return '\u{fffd}';
        };
        if first.is_ascii_hexdigit() {
            let mut value: u32 = 0;
            let mut digits = 0;
            while digits < 6 {
                match self.at(0) {
                    Some(c) if c.is_ascii_hexdigit() => {
                        value = value * 16 + c.to_digit(16).expect("hex digit");
                        self.pos += 1;
                        digits += 1;
                    }
                    _ => break,
                }
            }
            if matches!(self.at(0), Some(c) if is_ws(c)) {
                self.pos += 1;
            }
            // Null, surrogates and out-of-range escapes become U+FFFD, per the
            // CSS Syntax escape rules. `\0000` therefore cannot produce a NUL.
            if value == 0 || (0xd800..=0xdfff).contains(&value) || value > 0x0010_ffff {
                return '\u{fffd}';
            }
            return char::from_u32(value).unwrap_or('\u{fffd}');
        }
        self.pos += 1;
        first
    }

    fn consume_ident_sequence(&mut self) -> String {
        let mut out = String::new();
        loop {
            match self.at(0) {
                Some(c) if is_ident_char(c) => {
                    out.push(c);
                    self.pos += 1;
                }
                Some('\\') if self.valid_escape_at(0) => {
                    self.pos += 1;
                    out.push(self.consume_escape());
                }
                _ => break,
            }
        }
        out
    }

    fn consume_numeric(&mut self) -> Token {
        let start = self.pos;
        if matches!(self.at(0), Some('+') | Some('-')) {
            self.pos += 1;
        }
        while matches!(self.at(0), Some(c) if c.is_ascii_digit()) {
            self.pos += 1;
        }
        if self.at(0) == Some('.') && matches!(self.at(1), Some(c) if c.is_ascii_digit()) {
            self.pos += 2;
            while matches!(self.at(0), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if matches!(self.at(0), Some('e') | Some('E')) {
            let exponent = if matches!(self.at(1), Some('+') | Some('-')) {
                matches!(self.at(2), Some(c) if c.is_ascii_digit())
            } else {
                matches!(self.at(1), Some(c) if c.is_ascii_digit())
            };
            if exponent {
                self.pos += 2;
                while matches!(self.at(0), Some(c) if c.is_ascii_digit()) {
                    self.pos += 1;
                }
            }
        }
        let raw: String = self.chars[start..self.pos].iter().collect();
        if self.would_start_ident(0) {
            let unit = self.consume_ident_sequence();
            Token::Dimension(raw, unit)
        } else if self.at(0) == Some('%') {
            self.pos += 1;
            Token::Percentage(raw)
        } else {
            Token::Number(raw)
        }
    }

    fn consume_string(&mut self, quote: char) -> Result<Token, Failure> {
        self.pos += 1;
        let mut out = String::new();
        loop {
            match self.at(0) {
                None => {
                    return Err(syntax(
                        "malformed_string",
                        "string literal was not closed before end of stylesheet",
                    ))
                }
                Some('\n') => {
                    return Err(syntax(
                        "malformed_string",
                        "string literal contained a raw newline",
                    ))
                }
                Some(c) if c == quote => {
                    self.pos += 1;
                    return Ok(Token::Str(out));
                }
                Some('\\') => {
                    if self.at(1).is_none() {
                        self.pos += 1;
                    } else if self.at(1) == Some('\n') {
                        // Escaped newline: a line continuation inside a string.
                        self.pos += 2;
                    } else {
                        self.pos += 1;
                        out.push(self.consume_escape());
                    }
                }
                Some(c) => {
                    out.push(c);
                    self.pos += 1;
                }
            }
        }
    }

    /// Consumes an unquoted url token, `url(` already consumed.
    fn consume_url(&mut self) -> Result<Token, Failure> {
        while matches!(self.at(0), Some(c) if is_ws(c)) {
            self.pos += 1;
        }
        let mut out = String::new();
        loop {
            match self.at(0) {
                None => {
                    return Err(syntax(
                        "malformed_url",
                        "url() was not closed before end of stylesheet",
                    ))
                }
                Some(')') => {
                    self.pos += 1;
                    return Ok(Token::Url(out));
                }
                Some(c) if is_ws(c) => {
                    while matches!(self.at(0), Some(c) if is_ws(c)) {
                        self.pos += 1;
                    }
                    if self.at(0) == Some(')') {
                        self.pos += 1;
                        return Ok(Token::Url(out));
                    }
                    return Err(syntax(
                        "malformed_url",
                        "unquoted url() contained whitespace",
                    ));
                }
                Some('"') | Some('\'') | Some('(') => {
                    return Err(syntax(
                        "malformed_url",
                        "unquoted url() contained a quote or open paren",
                    ))
                }
                Some('\\') => {
                    if self.valid_escape_at(0) {
                        self.pos += 1;
                        out.push(self.consume_escape());
                    } else {
                        return Err(syntax(
                            "malformed_url",
                            "unquoted url() contained a stray backslash",
                        ));
                    }
                }
                Some(c) if (c as u32) <= 0x1f || c == '\u{7f}' => {
                    return Err(syntax(
                        "malformed_url",
                        "unquoted url() contained a control character",
                    ))
                }
                Some(c) => {
                    out.push(c);
                    self.pos += 1;
                }
            }
        }
    }

    fn consume_ident_like(&mut self) -> Result<Token, Failure> {
        let name = self.consume_ident_sequence();
        if self.at(0) != Some('(') {
            return Ok(Token::Ident(name));
        }
        self.pos += 1;
        if !name.eq_ignore_ascii_case("url") {
            return Ok(Token::Function(name));
        }
        let mut lookahead = 0;
        while matches!(self.at(lookahead), Some(c) if is_ws(c)) {
            lookahead += 1;
        }
        if matches!(self.at(lookahead), Some('"') | Some('\'')) {
            // `url( "x" )` is a function token followed by a string token.
            return Ok(Token::Function(name));
        }
        self.consume_url()
    }

    fn tokenize(mut self) -> Result<Vec<Token>, Failure> {
        let mut tokens = Vec::new();
        while let Some(c) = self.at(0) {
            let token = match c {
                '/' if self.at(1) == Some('*') => {
                    self.pos += 2;
                    let mut closed = false;
                    while let Some(c) = self.at(0) {
                        if c == '*' && self.at(1) == Some('/') {
                            self.pos += 2;
                            closed = true;
                            break;
                        }
                        self.pos += 1;
                    }
                    if !closed {
                        return Err(syntax(
                            "unterminated_comment",
                            "comment was not closed before end of stylesheet",
                        ));
                    }
                    // A comment is *not* dropped without trace. CSS Syntax
                    // removes it and leaves the tokens either side separate,
                    // but this module re-emits from its own token list and
                    // `serialize_tokens` only separates tokens where a
                    // `Whitespace` token exists. Emitting nothing here would
                    // therefore glue the neighbours together in the output —
                    // `u/**/rl(...)` inspected as `u` + `rl(` and re-emitted as
                    // `url(...)`. A separator token makes that fusion
                    // impossible: what the policy walk inspected is what the
                    // browser gets.
                    Token::Whitespace
                }
                c if is_ws(c) => {
                    while matches!(self.at(0), Some(c) if is_ws(c)) {
                        self.pos += 1;
                    }
                    Token::Whitespace
                }
                '"' | '\'' => self.consume_string(c)?,
                '#' => {
                    let ident_next = matches!(self.at(1), Some(c) if is_ident_char(c))
                        || self.valid_escape_at(1);
                    if ident_next {
                        self.pos += 1;
                        let is_id = self.would_start_ident(0);
                        Token::Hash(self.consume_ident_sequence(), is_id)
                    } else {
                        self.pos += 1;
                        Token::Delim('#')
                    }
                }
                '(' => {
                    self.pos += 1;
                    Token::LParen
                }
                ')' => {
                    self.pos += 1;
                    Token::RParen
                }
                '[' => {
                    self.pos += 1;
                    Token::LBracket
                }
                ']' => {
                    self.pos += 1;
                    Token::RBracket
                }
                '{' => {
                    self.pos += 1;
                    Token::LBrace
                }
                '}' => {
                    self.pos += 1;
                    Token::RBrace
                }
                ',' => {
                    self.pos += 1;
                    Token::Comma
                }
                ':' => {
                    self.pos += 1;
                    Token::Colon
                }
                ';' => {
                    self.pos += 1;
                    Token::Semicolon
                }
                '+' | '.' => {
                    if self.would_start_number(0) {
                        self.consume_numeric()
                    } else {
                        self.pos += 1;
                        Token::Delim(c)
                    }
                }
                '-' => {
                    if self.would_start_number(0) {
                        self.consume_numeric()
                    } else if self.at(1) == Some('-') && self.at(2) == Some('>') {
                        // CDC: carries no meaning for this parser, but must
                        // still separate its neighbours in the output. See the
                        // comment branch above.
                        self.pos += 3;
                        Token::Whitespace
                    } else if self.would_start_ident(0) {
                        self.consume_ident_like()?
                    } else {
                        self.pos += 1;
                        Token::Delim('-')
                    }
                }
                '<' => {
                    if self.at(1) == Some('!') && self.at(2) == Some('-') && self.at(3) == Some('-')
                    {
                        // CDO: same reasoning as CDC. `u<!--rl(...)` is the
                        // second spelling of the comment fusion vector.
                        self.pos += 4;
                        Token::Whitespace
                    } else {
                        self.pos += 1;
                        Token::Delim('<')
                    }
                }
                '@' => {
                    if self.would_start_ident(1) {
                        self.pos += 1;
                        Token::AtKeyword(self.consume_ident_sequence())
                    } else {
                        self.pos += 1;
                        Token::Delim('@')
                    }
                }
                '\\' => {
                    if self.valid_escape_at(0) {
                        self.consume_ident_like()?
                    } else {
                        // A backslash that starts no escape would be re-emitted
                        // next to a neighbour it did not escape in the source.
                        return Err(syntax(
                            "invalid_escape",
                            "stylesheet contained a backslash that starts no escape sequence",
                        ));
                    }
                }
                c if c.is_ascii_digit() => self.consume_numeric(),
                c if is_ident_start(c) => self.consume_ident_like()?,
                c => {
                    self.pos += 1;
                    Token::Delim(c)
                }
            };
            tokens.push(token);
        }
        Ok(tokens)
    }
}

// ---------------------------------------------------------------------------
// Serialisation
// ---------------------------------------------------------------------------

fn push_hex_escape(out: &mut String, c: char) {
    let _ = write!(out, "\\{:x} ", c as u32);
}

/// CSSOM "serialize an identifier". The output re-tokenizes to exactly the
/// input value, and can contain no structural character.
///
/// "Exactly the input value" is a claim about this function's output read as
/// an identifier. It is *not* a claim about the output of every caller:
/// `serialize_token` concatenates an identifier after numeric text for a
/// `Dimension`, where a unit of `e5` after a `1` would re-tokenize as the
/// number `1e5`. That composition is fixed there rather than here, because
/// only the caller knows what precedes the identifier.
///
/// `<` is hex-escaped for the reason given on `serialize_string`, and must be
/// escaped in *both* places: `\<` would put a bare `<` byte in the output, and
/// an HTML tokenizer scanning for `</style` does not care that CSS considers
/// it escaped.
fn serialize_ident(name: &str) -> String {
    if name == "-" {
        return "\\-".to_owned();
    }
    let mut out = String::with_capacity(name.len());
    for (index, c) in name.chars().enumerate() {
        let leading_digit = index == 0 && c.is_ascii_digit();
        let second_digit = index == 1 && c.is_ascii_digit() && name.starts_with('-');
        if c == '\0' {
            out.push('\u{fffd}');
        } else if (c as u32) <= 0x1f || c == '\u{7f}' || c == '<' || leading_digit || second_digit {
            push_hex_escape(&mut out, c);
        } else if (c as u32) >= 0x80 || c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            out.push(c);
        } else {
            out.push('\\');
            out.push(c);
        }
    }
    out
}

/// CSSOM "serialize a string". Always double-quoted; every control character
/// (including newlines) is hex-escaped, and quotes and backslashes are escaped,
/// so the result can never terminate early.
fn serialize_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '\0' => out.push('\u{fffd}'),
            '"' => out.push_str("\\\""),
            // `<` is hex-escaped so that the sheet can never contain the byte
            // sequence `</style>`. This module owns CSS, not HTML, but the
            // emitted sheet may be inlined into a <style> element by a later
            // lane, and the escape is free: CSS resolves it back to `<`.
            //
            // Strings are one of three places a `<` can reach the output. The
            // other two are `serialize_ident` and the `Delim` arm of
            // `serialize_token`, and both escape it too. Escaping only here
            // made this function's comment false in exactly the lane it names:
            // `--x: </style><svg onload=alert(1)>` is three delimiters and two
            // identifiers, no string anywhere, and it round-tripped verbatim.
            '<' => push_hex_escape(&mut out, c),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) <= 0x1f || c == '\u{7f}' => push_hex_escape(&mut out, c),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Hash values may legally start with a digit (`#0f0`), which
/// `serialize_ident` would escape into `#\\30 f0`. That is still correct CSS,
/// but it changes a colour literal into an id selector shape, so hash values
/// keep digits unescaped while every other character goes through the
/// identifier escaper.
fn serialize_hash(value: &str) -> String {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return value.to_owned();
    }
    serialize_ident(value)
}

/// Serialises a dimension's unit, given the numeric text it will follow.
///
/// Returns the ordinary identifier serialisation unless the pair would fuse
/// into a single number, i.e. `raw` carries no exponent yet and `unit` begins
/// an exponent (`e5`, `e-5`, `E+5`). In that case the leading `e`/`E` is
/// hex-escaped, which no CSS engine reads as part of a number.
fn serialize_unit(raw: &str, unit: &str) -> String {
    let starts_exponent = {
        let mut rest = unit.chars().skip(1).peekable();
        let signed = matches!(rest.peek(), Some('+') | Some('-'));
        if signed {
            rest.next();
        }
        unit.starts_with(['e', 'E']) && matches!(rest.next(), Some(c) if c.is_ascii_digit())
    };
    if !starts_exponent || raw.contains(['e', 'E']) {
        return serialize_ident(unit);
    }
    let mut out = String::with_capacity(unit.len() + 4);
    push_hex_escape(&mut out, unit.chars().next().expect("unit is non-empty"));
    out.push_str(&serialize_ident(&unit[1..]));
    out
}

fn serialize_token(token: &Token) -> String {
    match token {
        Token::Ident(name) => serialize_ident(name),
        Token::Function(name) => format!("{}(", serialize_ident(name)),
        Token::AtKeyword(name) => format!("@{}", serialize_ident(name)),
        // Non-identifier hash values (e.g. `#0f0`) serialise through the
        // identifier escaper too: it is a superset and adds no escape for
        // hex-digit-only values beyond the leading-digit one, which a colour
        // hash does not need because `#` already separates it.
        Token::Hash(value, _) => format!("#{}", serialize_hash(value)),
        Token::Str(value) => serialize_string(value),
        // Unquoted url tokens are normalised to the quoted function form.
        Token::Url(value) => format!("url({})", serialize_string(value)),
        // `<` is escaped here for the same reason it is escaped in strings and
        // identifiers; `>` and `/` are left alone, because `</style>` needs the
        // `<`, and the child combinator and the shorthand slash are the two
        // most common delimiters in real author CSS. `serialize_tokens` adds
        // the separators this escape needs — see there.
        Token::Delim('<') => {
            let mut out = String::new();
            push_hex_escape(&mut out, '<');
            out
        }
        Token::Delim(c) => c.to_string(),
        Token::Number(raw) => raw.clone(),
        // A unit is an identifier, but it is emitted *after* numeric text, and
        // `1` followed by the unit `e5` re-tokenizes as the single number
        // `1e5` — the unit disappears. Escaping the leading `e` keeps the two
        // tokens two tokens. Only an `e`/`E` that could begin an exponent is
        // escaped, so `1em` stays `1em`, and a number that already carries an
        // exponent cannot acquire a second one.
        Token::Dimension(raw, unit) => {
            format!("{raw}{}", serialize_unit(raw, unit))
        }
        Token::Percentage(raw) => format!("{raw}%"),
        Token::Whitespace => " ".to_owned(),
        Token::Colon => ":".to_owned(),
        Token::Semicolon => ";".to_owned(),
        Token::Comma => ",".to_owned(),
        Token::LBracket => "[".to_owned(),
        Token::RBracket => "]".to_owned(),
        Token::LParen => "(".to_owned(),
        Token::RParen => ")".to_owned(),
        Token::LBrace => "{".to_owned(),
        Token::RBrace => "}".to_owned(),
    }
}

fn serialize_tokens(tokens: &[Token]) -> String {
    let mut out = String::new();
    let mut pending_space = false;
    for token in tokens {
        if matches!(token, Token::Whitespace) {
            pending_space = !out.is_empty();
            continue;
        }
        // An escaped `<` is emitted as `\3c `, which the tokenizer reads as the
        // start of an *identifier*: left touching its neighbours it would fuse
        // with them, and `.a<b` would come back as the single identifier
        // `a<b`. That is the same fusion the comment separator exists to
        // prevent (see `tokenize`), so the escape carries its own separators.
        // The escape's own trailing space cannot serve: an escape consumes one
        // whitespace, so it takes a second to end the identifier.
        let escaped_delim = matches!(token, Token::Delim('<'));
        if pending_space || (escaped_delim && !out.is_empty()) {
            out.push(' ');
        }
        pending_space = escaped_delim;
        out.push_str(&serialize_token(token));
    }
    out
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum Node {
    Rule {
        prelude: Vec<Token>,
        body: Vec<Node>,
    },
    AtRule {
        name: String,
        prelude: Vec<Token>,
        body: Option<Vec<Node>>,
    },
    Declaration {
        property: String,
        value: Vec<Token>,
    },
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    /// Blocks currently open. See `MAX_NESTING_DEPTH`.
    depth: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    /// Parses the body of a `{ ... }` block, one level deeper.
    ///
    /// Every recursive entry into `parse_nodes` goes through here, so the cap
    /// is enforced before the stack frame that would overflow is pushed. On
    /// rejection the depth is not restored, because the whole parse is
    /// abandoned.
    fn parse_block(&mut self) -> Result<Vec<Node>, Failure> {
        self.depth += 1;
        if self.depth > MAX_NESTING_DEPTH {
            return Err(Failure::new(
                "css_limit_exceeded",
                "parse",
                format!("stylesheet nests blocks more than {MAX_NESTING_DEPTH} deep"),
            )
            .detail("rule", "nesting_depth")
            .detail("maximum", MAX_NESTING_DEPTH as u64));
        }
        let nodes = self.parse_nodes(false);
        self.depth -= 1;
        nodes
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(Token::Whitespace)) {
            self.pos += 1;
        }
    }

    fn parse_nodes(&mut self, top_level: bool) -> Result<Vec<Node>, Failure> {
        let mut nodes = Vec::new();
        loop {
            match self.peek() {
                None => {
                    if top_level {
                        break;
                    }
                    return Err(syntax(
                        "unbalanced_block",
                        "a block was not closed before end of stylesheet",
                    ));
                }
                Some(Token::RBrace) => {
                    if top_level {
                        return Err(syntax(
                            "unbalanced_block",
                            "stylesheet contained a block close with no matching open",
                        ));
                    }
                    self.pos += 1;
                    break;
                }
                Some(Token::Whitespace) | Some(Token::Semicolon) => {
                    self.pos += 1;
                }
                Some(Token::AtKeyword(_)) => nodes.push(self.parse_at_rule()?),
                _ => {
                    if !top_level && self.looks_like_declaration() {
                        nodes.push(self.parse_declaration()?);
                    } else {
                        nodes.push(self.parse_qualified_rule()?);
                    }
                }
            }
        }
        Ok(nodes)
    }

    /// Distinguishes `color: red` from `a:hover { ... }`. Both start
    /// `<ident> :`, so the decision needs a scan: a top-level `{` before the
    /// terminating `;` or `}` means it was a nested style rule after all.
    /// Custom properties are exempt because `{}` is legal inside their value.
    fn looks_like_declaration(&self) -> bool {
        let mut index = self.pos;
        let Some(Token::Ident(name)) = self.tokens.get(index) else {
            return false;
        };
        index += 1;
        while matches!(self.tokens.get(index), Some(Token::Whitespace)) {
            index += 1;
        }
        if !matches!(self.tokens.get(index), Some(Token::Colon)) {
            return false;
        }
        if name.starts_with("--") {
            return true;
        }
        index += 1;
        let mut depth = 0usize;
        while let Some(token) = self.tokens.get(index) {
            match token {
                Token::LParen | Token::LBracket => depth += 1,
                Token::RParen | Token::RBracket => depth = depth.saturating_sub(1),
                Token::LBrace if depth == 0 => return false,
                Token::LBrace => depth += 1,
                Token::RBrace if depth == 0 => return true,
                Token::RBrace => depth = depth.saturating_sub(1),
                Token::Semicolon if depth == 0 => return true,
                _ => {}
            }
            index += 1;
        }
        true
    }

    fn parse_declaration(&mut self) -> Result<Node, Failure> {
        let Some(Token::Ident(property)) = self.peek().cloned() else {
            return Err(syntax("invalid_declaration", "expected a property name"));
        };
        self.pos += 1;
        self.skip_ws();
        self.pos += 1; // the colon, already confirmed by looks_like_declaration
        let mut value = Vec::new();
        let mut depth = 0usize;
        loop {
            match self.peek() {
                None => {
                    return Err(syntax(
                        "unbalanced_block",
                        "a declaration was not closed before end of stylesheet",
                    ))
                }
                Some(Token::Semicolon) if depth == 0 => {
                    self.pos += 1;
                    break;
                }
                Some(Token::RBrace) if depth == 0 => break,
                Some(token) => {
                    match token {
                        Token::LParen | Token::LBracket | Token::LBrace => depth += 1,
                        Token::RParen | Token::RBracket | Token::RBrace => {
                            depth = depth.saturating_sub(1)
                        }
                        _ => {}
                    }
                    value.push(token.clone());
                    self.pos += 1;
                }
            }
        }
        while matches!(value.last(), Some(Token::Whitespace)) {
            value.pop();
        }
        if value.is_empty() {
            return Err(syntax(
                "invalid_declaration",
                format!("declaration `{property}` had an empty value"),
            ));
        }
        Ok(Node::Declaration { property, value })
    }

    fn collect_prelude(&mut self, stop_on_semicolon: bool) -> (Vec<Token>, Option<Token>) {
        let mut prelude = Vec::new();
        let mut depth = 0usize;
        loop {
            match self.peek().cloned() {
                None => return (prelude, None),
                Some(Token::LBrace) if depth == 0 => {
                    self.pos += 1;
                    return (prelude, Some(Token::LBrace));
                }
                Some(Token::Semicolon) if depth == 0 && stop_on_semicolon => {
                    self.pos += 1;
                    return (prelude, Some(Token::Semicolon));
                }
                Some(Token::RBrace) if depth == 0 => return (prelude, Some(Token::RBrace)),
                Some(token) => {
                    match token {
                        Token::LParen | Token::LBracket => depth += 1,
                        Token::RParen | Token::RBracket => depth = depth.saturating_sub(1),
                        _ => {}
                    }
                    prelude.push(token);
                    self.pos += 1;
                }
            }
        }
    }

    fn parse_qualified_rule(&mut self) -> Result<Node, Failure> {
        let (prelude, terminator) = self.collect_prelude(false);
        // Before the block/terminator check, so a *statement*-shaped forgery
        // (`@/**/import "x";`, which never opens a block) is named for what it
        // is rather than reported as a missing declaration block.
        check_selector_prelude(&prelude)?;
        if terminator != Some(Token::LBrace) {
            return Err(syntax(
                "missing_block",
                "a style rule had no declaration block",
            ));
        }
        if prelude.iter().all(|t| matches!(t, Token::Whitespace)) {
            return Err(syntax(
                "empty_prelude",
                "a style rule had an empty selector",
            ));
        }
        let body = self.parse_block()?;
        Ok(Node::Rule { prelude, body })
    }

    fn parse_at_rule(&mut self) -> Result<Node, Failure> {
        let Some(Token::AtKeyword(name)) = self.peek().cloned() else {
            return Err(syntax("invalid_at_rule", "expected an at-rule name"));
        };
        self.pos += 1;
        let (prelude, terminator) = self.collect_prelude(true);
        let body = match terminator {
            Some(Token::LBrace) => Some(self.parse_block()?),
            _ => None,
        };
        Ok(Node::AtRule {
            name,
            prelude,
            body,
        })
    }
}

// ---------------------------------------------------------------------------
// Policy walk and rewrites
// ---------------------------------------------------------------------------

struct Walk<'a> {
    class_prefix: &'a str,
    rules: usize,
    flags: BTreeSet<Flag>,
}

impl Walk<'_> {
    fn visit_all(&mut self, nodes: &mut [Node]) -> Result<(), Failure> {
        for node in nodes.iter_mut() {
            self.visit(node)?;
        }
        Ok(())
    }

    fn visit(&mut self, node: &mut Node) -> Result<(), Failure> {
        match node {
            Node::Rule { prelude, body } => {
                self.count_rule()?;
                check_selector_prelude(prelude)?;
                self.rewrite_selector(prelude);
                self.check_tokens(prelude)?;
                self.visit_all(body)
            }
            Node::AtRule {
                name,
                prelude,
                body,
            } => {
                self.count_rule()?;
                self.check_at_rule(name)?;
                // Class selectors can appear in at-rule preludes (`@scope
                // (.card)`), and a `.ident` sequence is meaningless in every
                // other at-rule prelude, so the rewrite is applied uniformly.
                self.rewrite_selector(prelude);
                self.check_tokens(prelude)?;
                if let Some(body) = body {
                    self.visit_all(body)?;
                }
                Ok(())
            }
            Node::Declaration { property, value } => {
                self.check_property(property);
                self.check_tokens(value)
            }
        }
    }

    fn count_rule(&mut self) -> Result<(), Failure> {
        self.rules += 1;
        if self.rules > MAX_RULES {
            return Err(Failure::new(
                "css_limit_exceeded",
                "policy",
                format!("stylesheet declares more than {MAX_RULES} rules"),
            )
            .detail("rule", "rule_limit")
            .detail("maximum", MAX_RULES as u64));
        }
        Ok(())
    }

    fn check_at_rule(&mut self, name: &str) -> Result<(), Failure> {
        let lower = name.to_lowercase();
        let mut bare = lower.as_str();
        for prefix in VENDOR_PREFIXES {
            if let Some(stripped) = bare.strip_prefix(prefix) {
                bare = stripped;
                break;
            }
        }
        if bare == "import" {
            // Rejected wherever it appears. A re-serialiser that hoisted a
            // nested `@import` to the top of the sheet would convert a
            // contained one into a full escape, so position is not a defence.
            return Err(policy(
                "forbidden_import",
                "@import is forbidden in author CSS at any position",
            )
            .detail("at_rule", name.to_owned()));
        }
        if FORBIDDEN_AT_RULES.contains(&bare) {
            return Err(policy(
                "forbidden_at_rule",
                format!("@{bare} registers a global name and is forbidden at any nesting depth"),
            )
            .detail("at_rule", name.to_owned()));
        }
        if bare == "layer" {
            // Deliberately allowed, and deliberately not silent. A layer name
            // is document-global like the names on the ban list above, but it
            // is global *ordering* rather than a global definition: it cannot
            // fetch, cannot define an animation or a registered property, and
            // cannot lift a rule out of the `@scope` wrapper.
            //
            // This comment used to justify the decision with "unlayered rules
            // outrank every layer, so an author can only lower their own
            // priority". **That is false**, and was demonstrated false: the
            // cascade *reverses* layer order for `!important` declarations,
            // and unlayered is the lowest of the reversed order, so a layered
            // author `!important` beat the host's `prefers-reduced-motion`
            // guard. Layering cannot be relied on to keep an author below the
            // host.
            //
            // What actually bounds the reach is two other properties:
            //
            // 1. `@scope (root) to (limit)` confines every author rule to the
            //    artifact subtree, so winning the cascade wins it only over
            //    elements the author already owns. Priority is not reach.
            // 2. The author sheet loads *after* the host sheet, so on equal
            //    specificity and equal importance the author already wins with
            //    or without `@layer`. Allowing it concedes nothing that
            //    document order had not conceded already.
            //
            // **Point 2 is a load-order dependency, and it is the whole
            // argument.** If the author sheet ever loads before the host's, or
            // the host adopts layers of its own, this reasoning expires and
            // `@layer` becomes a ban. The flag exists so that the day that
            // happens, the usage is already visible rather than needing to be
            // discovered.
            self.flags.insert(Flag {
                rule: "global_layer_name",
                name: lower,
            });
            return Ok(());
        }
        if !KNOWN_AT_RULES.contains(&lower.as_str()) {
            self.flags.insert(Flag {
                rule: "unknown_at_rule",
                name: lower,
            });
        }
        Ok(())
    }

    fn check_property(&mut self, property: &str) {
        if property.starts_with("--") {
            return;
        }
        let lower = property.to_lowercase();
        if !KNOWN_PROPERTIES.contains(&lower.as_str()) {
            self.flags.insert(Flag {
                rule: "unknown_property",
                name: lower,
            });
        }
    }

    /// Rewrites `.foo` to `.{prefix}foo` in a selector token list.
    ///
    /// Attribute selectors are skipped wholesale, so `[data-x=a.b]` keeps its
    /// dot. Strings are separate tokens and are never touched, so
    /// `[data-x=".a"]` and `content: ".a"` are also left alone.
    fn rewrite_selector(&mut self, tokens: &mut [Token]) {
        let mut bracket_depth = 0usize;
        for index in 0..tokens.len() {
            match &tokens[index] {
                Token::LBracket => {
                    bracket_depth += 1;
                    continue;
                }
                Token::RBracket => {
                    bracket_depth = bracket_depth.saturating_sub(1);
                    continue;
                }
                Token::Hash(value, true) if bracket_depth == 0 => {
                    // Id selectors carry the same host-collision risk as class
                    // selectors but are not rewritten here, because the id
                    // rewrite (if any) belongs to the HTML lane. Make it
                    // visible rather than silent.
                    self.flags.insert(Flag {
                        rule: "id_selector",
                        name: value.clone(),
                    });
                    continue;
                }
                Token::Delim('.') if bracket_depth == 0 => {}
                _ => continue,
            }
            // `.` immediately followed by an identifier is a class selector.
            // `.5em` never reaches here: it tokenizes as a dimension.
            if let Some(Token::Ident(name)) = tokens.get(index + 1) {
                let prefixed = format!("{}{}", self.class_prefix, name);
                tokens[index + 1] = Token::Ident(prefixed);
            }
        }
    }

    fn check_tokens(&mut self, tokens: &[Token]) -> Result<(), Failure> {
        for (index, token) in tokens.iter().enumerate() {
            match token {
                Token::Url(value) => check_url(value)?,
                Token::Function(name) => {
                    let lower = name.to_lowercase();
                    let mut bare = lower.as_str();
                    for prefix in VENDOR_PREFIXES {
                        if let Some(stripped) = bare.strip_prefix(prefix) {
                            bare = stripped;
                            break;
                        }
                    }
                    if FORBIDDEN_URL_FUNCTIONS.contains(&lower.as_str())
                        || FORBIDDEN_URL_FUNCTIONS.contains(&bare)
                    {
                        return Err(policy(
                            "forbidden_url_function",
                            format!("{lower}() takes bare string URLs and is forbidden"),
                        )
                        .detail("function", lower));
                    }
                    if FORBIDDEN_ELEMENT_FUNCTIONS.contains(&lower.as_str())
                        || FORBIDDEN_ELEMENT_FUNCTIONS.contains(&bare)
                    {
                        return Err(policy(
                            "forbidden_element_function",
                            format!("{lower}() paints a same-document element and is forbidden"),
                        )
                        .detail("function", lower));
                    }
                    if !KNOWN_FUNCTIONS.contains(&lower.as_str()) {
                        self.flags.insert(Flag {
                            rule: "unknown_function",
                            name: lower.clone(),
                        });
                    }
                    if lower == "url" {
                        let mut next = index + 1;
                        while matches!(tokens.get(next), Some(Token::Whitespace)) {
                            next += 1;
                        }
                        let Some(Token::Str(value)) = tokens.get(next) else {
                            return Err(syntax(
                                "malformed_url",
                                "url() argument was not a single string",
                            ));
                        };
                        check_url(value)?;
                        next += 1;
                        while matches!(tokens.get(next), Some(Token::Whitespace)) {
                            next += 1;
                        }
                        if !matches!(tokens.get(next), Some(Token::RParen)) {
                            // A second argument is invalid CSS anyway; refusing
                            // it keeps the checked string and the emitted url
                            // in one-to-one correspondence.
                            return Err(syntax(
                                "malformed_url",
                                "url() took more than one argument",
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Rejects a qualified rule whose selector carries a bare `@` delimiter.
///
/// `@` followed by anything that does not start an identifier tokenizes as
/// `Delim('@')`, not `AtKeyword`, so `check_at_rule` is never reached: the
/// construct parses as a *qualified rule* with prelude `[Delim('@'),
/// Ident("font-face")]`. `@/**/font-face { ... }` and `@<!--keyframes { ... }`
/// are the two spellings. Separating the tokens on emission (see the tokenizer)
/// already breaks the glue, but that defence is a serialisation property and
/// this one is a parse-tree property: a selector never legitimately contains a
/// bare `@`, so refuse the shape outright rather than relying on the emitter.
fn check_selector_prelude(prelude: &[Token]) -> Result<(), Failure> {
    let Some(index) = prelude
        .iter()
        .position(|token| matches!(token, Token::Delim('@')))
    else {
        return Ok(());
    };
    let masked = prelude[index + 1..]
        .iter()
        .find_map(|token| match token {
            Token::Ident(name) => Some(name.to_lowercase()),
            Token::Whitespace => None,
            _ => Some(String::new()),
        })
        .unwrap_or_default();
    Err(policy(
        "masked_at_rule",
        "a style rule selector contained a bare `@`, which is an at-rule keyword \
         broken up by a comment or CDO rather than a selector",
    )
    .detail("at_rule", masked))
}

fn check_url(value: &str) -> Result<(), Failure> {
    // `is_ws` is CSS Syntax whitespace, and only that. `str::trim` uses
    // `char::is_whitespace`, which is Unicode's definition and additionally
    // includes U+00A0, U+0085, U+1680, U+2000–200A, U+2028, U+2029 and U+3000.
    // None of those are CSS whitespace: neither the URL parser nor any browser
    // strips them, and `serialize_string` re-emits them verbatim. Trimming them
    // here inspected a *different string* from the one emitted, so
    // `url("\u{a0}data:x/../../probe")` passed the data-URL test and then
    // reached the network as a same-origin request.
    let trimmed = value.trim_matches(is_ws);
    // Backstop for anything the trim rule above does not anticipate: a URL that
    // does not *begin* with a scheme character or a fragment marker cannot be
    // the `data:` or `#...` this policy allows, whatever it goes on to say.
    // Checked on the same string that is emitted.
    if !matches!(trimmed.chars().next(), Some(c) if c.is_ascii_alphabetic() || c == '#') {
        return Err(policy(
            "forbidden_url",
            "CSS urls must begin with a scheme letter or `#`; leading whitespace, \
             control characters and other prefixes are rejected",
        )
        .detail("url", trimmed.to_owned()));
    }
    let lower = trimmed.to_lowercase();
    if lower.starts_with("data:") || trimmed.starts_with('#') {
        return Ok(());
    }
    Err(policy(
        "forbidden_url",
        "CSS urls must be data URLs or bare fragments; every other url is live network egress",
    )
    .detail("url", trimmed.to_owned()))
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

fn emit(nodes: &[Node], indent: usize, out: &mut String) {
    let pad = "  ".repeat(indent);
    for node in nodes {
        match node {
            Node::Rule { prelude, body } => {
                let _ = writeln!(out, "{pad}{} {{", serialize_tokens(prelude));
                emit(body, indent + 1, out);
                let _ = writeln!(out, "{pad}}}");
            }
            Node::AtRule {
                name,
                prelude,
                body,
            } => {
                let head = serialize_tokens(prelude);
                let at = serialize_ident(name);
                match body {
                    Some(body) => {
                        if head.is_empty() {
                            let _ = writeln!(out, "{pad}@{at} {{");
                        } else {
                            let _ = writeln!(out, "{pad}@{at} {head} {{");
                        }
                        emit(body, indent + 1, out);
                        let _ = writeln!(out, "{pad}}}");
                    }
                    None => {
                        if head.is_empty() {
                            let _ = writeln!(out, "{pad}@{at};");
                        } else {
                            let _ = writeln!(out, "{pad}@{at} {head};");
                        }
                    }
                }
            }
            Node::Declaration { property, value } => {
                let _ = writeln!(
                    out,
                    "{pad}{}: {};",
                    serialize_ident(property),
                    serialize_tokens(value)
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Caller inputs
// ---------------------------------------------------------------------------

/// Validates the caller-supplied class prefix. The prefix is interpolated into
/// selectors, so it is held to an identifier shape rather than trusted.
fn validated_prefix(class_prefix: &str) -> Result<(), Failure> {
    let mut chars = class_prefix.chars();
    let ok = match chars.next() {
        Some(c) => {
            (c.is_ascii_alphabetic() || c == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        }
        None => false,
    };
    if ok {
        return Ok(());
    }
    Err(policy(
        "invalid_class_prefix",
        "class prefix must be a non-empty ASCII identifier",
    )
    .detail("class_prefix", class_prefix.to_owned()))
}

/// Re-serialises a caller-supplied scope selector through this module's own
/// tokenizer, so even the host's inputs cannot introduce structure.
fn validated_scope_selector(selector: &str, which: &'static str) -> Result<String, Failure> {
    let tokens = Tokenizer::new(selector)
        .tokenize()
        .map_err(|_| invalid_scope(which, selector))?;
    if tokens.is_empty()
        || tokens.iter().any(|token| {
            matches!(
                token,
                Token::LBrace
                    | Token::RBrace
                    | Token::Semicolon
                    | Token::AtKeyword(_)
                    | Token::Url(_)
            )
        })
    {
        return Err(invalid_scope(which, selector));
    }
    let mut depth = 0i64;
    for token in &tokens {
        match token {
            Token::LParen | Token::LBracket => depth += 1,
            Token::RParen | Token::RBracket => depth -= 1,
            _ => {}
        }
        if depth < 0 {
            return Err(invalid_scope(which, selector));
        }
    }
    if depth != 0 {
        return Err(invalid_scope(which, selector));
    }
    Ok(serialize_tokens(&tokens))
}

fn invalid_scope(which: &'static str, selector: &str) -> Failure {
    policy(
        "invalid_scope_selector",
        format!("{which} is not a usable scope selector"),
    )
    .detail("selector", selector.to_owned())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Validates an author stylesheet and returns it rewritten, scoped and
/// re-serialised, or a named-rule failure.
///
/// `class_prefix` is prepended to every class selector. `scope_root` and
/// `scope_limit` are selectors for the generated
/// `@scope (root) to (limit) { ... }` wrapper.
pub fn validate(
    source: &str,
    class_prefix: &str,
    scope_root: &str,
    scope_limit: &str,
) -> Result<StyleSheet, Failure> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(Failure::new(
            "css_source_too_large",
            "source",
            format!("author CSS exceeds {} KiB UTF-8", MAX_SOURCE_BYTES / 1024),
        )
        .detail("rule", "source_bytes")
        .detail("limit", "source_utf8_bytes")
        .detail("maximum", MAX_SOURCE_BYTES as u64));
    }
    if source.starts_with('\u{feff}') {
        return Err(Failure::new(
            "css_policy_violation",
            "source",
            "author CSS must not begin with a UTF-8 BOM",
        )
        .detail("rule", "utf8_bom"));
    }
    validated_prefix(class_prefix)?;
    let root = validated_scope_selector(scope_root, "scope root")?;
    let limit = validated_scope_selector(scope_limit, "scope limit")?;

    let tokens = Tokenizer::new(source).tokenize()?;
    let mut parser = Parser {
        tokens,
        pos: 0,
        depth: 0,
    };
    let mut nodes = parser.parse_nodes(true)?;

    let mut walk = Walk {
        class_prefix,
        rules: 0,
        flags: BTreeSet::new(),
    };
    walk.visit_all(&mut nodes)?;

    let mut body = String::new();
    emit(&nodes, 1, &mut body);
    let css = format!("@scope ({root}) to ({limit}) {{\n{body}}}\n");
    let sha256 = hex::encode(Sha256::digest(css.as_bytes()));
    Ok(StyleSheet {
        css,
        sha256,
        rules: walk.rules,
        flags: walk.flags.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "px-";
    const ROOT: &str = "#a-root";
    const LIMIT: &str = ".a-limit";

    fn ok(source: &str) -> StyleSheet {
        validate(source, PREFIX, ROOT, LIMIT).expect("stylesheet should validate")
    }

    fn rejected(source: &str) -> Failure {
        validate(source, PREFIX, ROOT, LIMIT).expect_err("stylesheet should be rejected")
    }

    fn rule_of(source: &str) -> String {
        rejected(source)
            .rule()
            .expect("failure names a rule")
            .to_owned()
    }

    // -- shape -------------------------------------------------------------

    #[test]
    fn emits_scope_wrapper_and_prefixed_classes() {
        let sheet = ok(".card { color: red; }");
        assert_eq!(
            sheet.css,
            "@scope (#a-root) to (.a-limit) {\n  .px-card {\n    color: red;\n  }\n}\n"
        );
        assert_eq!(sheet.rules, 1);
        assert!(sheet.flags.is_empty(), "{:?}", sheet.flags);
        assert_eq!(
            sheet.sha256,
            hex::encode(Sha256::digest(sheet.css.as_bytes()))
        );
    }

    /// The corpus matters more than the assertion. This test used to run on
    /// `.a { color: red }` alone, which exercises no construct whose emission
    /// can go wrong. Any comment-bearing input finds token fusion on the first
    /// pass, and `1//**/*2` finds a comment forged in the *output* — so the
    /// corpus deliberately carries comments, CDO/CDC, at-rules, urls, strings,
    /// escapes and nesting.
    const ROUND_TRIP_CORPUS: &[&str] = &[
        "@media (min-width: 600px) { .a > .b { color: red } }",
        ".a { /* c */ color: red; /* c */ }",
        ".a/**/.b { color: red }",
        ".a { color: r/**/ed }",
        ".a { z-index: 1//**/*2 }",
        ".a { width: 1/**/0px }",
        "<!-- .a { color: red } -->",
        ".a { background: u/**/rl(\"data:text/plain,x\") }",
        ".a { background: url(\"data:text/plain,a)b\") no-repeat }",
        ".a { clip-path: url(#clip) }",
        "@layer base { @media screen { .a:hover { color: red } } }",
        "@supports (display: grid) { .a { --x: {color:red}; color: blue } }",
        ".a { content: \"} .evil { color: red }\" }",
        ".\\31 23 { color: red }",
        ".a[data-x=\".b\"] { color: red }",
        "@wibble x { .a { wibble-thing: 3 } }",
        ".a { color: red !important }",
        "#id .a { color: red }",
    ];

    #[test]
    fn output_is_deterministic_and_reparses() {
        for source in ROUND_TRIP_CORPUS {
            let first = ok(source);
            let second = ok(source);
            assert_eq!(first.css, second.css, "{source}");
            assert_eq!(first.sha256, second.sha256, "{source}");
            // The emitted sheet is itself accepted by this validator, which is
            // the cheapest available check that emission never produces a
            // construct the parser rejects — and, since the emitter re-runs the
            // whole policy, that emission never produces a construct the policy
            // would have refused in the source.
            let round_trip = ok(&first.css);
            let third = ok(&round_trip.css);
            // No pass may forge a comment in its own output. `1//**/*2` emitted
            // `1/*2`, which opened one: the next pass failed with
            // `unterminated_comment`, and Chromium silently dropped every rule
            // after it.
            for pass in [&first, &round_trip, &third] {
                assert!(!pass.css.contains("/*"), "{source}: {}", pass.css);
            }
        }
    }

    #[test]
    fn round_trip_corpus_preserves_the_prefix() {
        let sheet = ok("@media (min-width: 600px) { .a > .b { color: red } }");
        let round_trip = ok(&sheet.css);
        assert!(round_trip.css.contains(".px-px-a"), "{}", round_trip.css);
    }

    // -- block-closing escape attempts -------------------------------------

    #[test]
    fn author_cannot_close_the_generated_block() {
        // The historical escape: close the wrapper, reopen a never-matching
        // scope, and land a rule on a real host drop target.
        let source = concat!(
            ".ok { color: red; }\n",
            "}\n",
            "@scope (.never-matches) to (.nothing) {\n",
            "  .safe-drop-target { content: \"Done - safe to send\"; }\n",
            "}\n"
        );
        assert_eq!(rule_of(source), "unbalanced_block");
    }

    #[test]
    fn drop_target_class_is_prefixed_not_landed() {
        let sheet = ok(".safe-drop-target { content: \"Done - safe to send\"; }");
        assert!(sheet.css.contains(".px-safe-drop-target"), "{}", sheet.css);
        assert!(!sheet.css.contains("{.safe-drop-target"), "{}", sheet.css);
        assert!(!sheet.css.contains(" .safe-drop-target"), "{}", sheet.css);
        assert_eq!(sheet.css.matches("@scope").count(), 1);
    }

    #[test]
    fn unclosed_block_is_rejected() {
        assert_eq!(rule_of(".a { color: red;"), "unbalanced_block");
    }

    #[test]
    fn empty_selector_is_rejected() {
        assert_eq!(rule_of("{ color: red }"), "empty_prelude");
    }

    // -- strings must not be read as structure -----------------------------

    #[test]
    fn content_at_import_is_not_an_at_rule() {
        let sheet = ok(".a { content: \"@import url(https://evil.example/x.css)\"; }");
        assert_eq!(sheet.rules, 1);
        assert!(
            sheet
                .css
                .contains("content: \"@import url(https://evil.example/x.css)\""),
            "{}",
            sheet.css
        );
    }

    #[test]
    fn content_brace_does_not_inflate_the_rule_count() {
        let sheet = ok(".a { content: \"{\"; }\n.b { content: \"}\"; }");
        assert_eq!(sheet.rules, 2);
        assert!(sheet.css.contains("content: \"{\";"), "{}", sheet.css);
        assert!(sheet.css.contains("content: \"}\";"), "{}", sheet.css);
    }

    #[test]
    fn braces_in_strings_do_not_open_or_close_blocks() {
        let sheet = ok(".a { content: \"} .evil { color: red; \"; }");
        assert_eq!(sheet.rules, 1);
        // The hostile text survives verbatim but stays inside one string token
        // in one declaration: it opened and closed nothing.
        assert!(
            sheet.css.contains("content: \"} .evil { color: red; \";"),
            "{}",
            sheet.css
        );
        assert_eq!(sheet.css.lines().count(), 5, "{}", sheet.css);
    }

    #[test]
    fn style_end_tag_in_a_string_is_escaped() {
        let sheet = ok(".a { content: \"</style><script>\"; }");
        assert!(!sheet.css.contains("</style>"), "{}", sheet.css);
        assert!(sheet.css.contains("\\3c "), "{}", sheet.css);
    }

    /// The string escape above is true but was not the invariant it stood for.
    /// `<`, `/` and `>` outside a string are `Delim` tokens, which were emitted
    /// raw and adjacent, so `--x: </style><svg/onload=alert(1)>` round-tripped
    /// byte-for-byte. Inlined into a `<style>` element that terminates the
    /// sheet early and lands an `<svg>` in the host DOM. Not reachable through
    /// today's `<link rel=stylesheet>` delivery, but the escape in
    /// `serialize_string` exists precisely for the lane that would be.
    #[test]
    fn style_end_tag_cannot_be_assembled_from_delimiters() {
        for source in [
            "p { --x: </style><svg/onload=alert(1)>; }",
            ".a { --x: <\\2f style> }",
            "p { --x: </sty/**/le> }",
        ] {
            let sheet = ok(source);
            assert!(
                !sheet.css.contains('<'),
                "{source} emitted a raw `<`: {}",
                sheet.css
            );
            assert!(sheet.css.contains("\\3c "), "{source}: {}", sheet.css);
            // And the escape survives its own output: re-validating must not
            // resolve it back to a raw `<`.
            assert!(!ok(&sheet.css).css.contains('<'), "{source}: {}", sheet.css);
        }
    }

    /// The `<` escape must not glue its neighbours together. `serialize_ident`
    /// emits `\3c ` as an identifier escape, whose trailing space the
    /// tokenizer consumes, so an unseparated `a<b` would come back as the
    /// single identifier `a<b` — the very fusion the comment separator exists
    /// to prevent.
    #[test]
    fn the_escaped_delimiter_does_not_fuse_its_neighbours() {
        let sheet = ok("@media (400px < width) { .a { color: red } }");
        let round_trip = ok(&sheet.css);
        assert!(round_trip.css.contains("400px"), "{}", round_trip.css);
        assert!(round_trip.css.contains("width"), "{}", round_trip.css);
        // `>` is untouched: `</style>` needs a `<`, and the child combinator is
        // the single most common delimiter in real selectors.
        let child = ok(".a > .b { color: red }");
        assert!(child.css.contains(".px-a > .px-b"), "{}", child.css);
    }

    #[test]
    fn raw_newline_in_a_string_is_rejected() {
        assert_eq!(rule_of(".a { content: \"oops\n\"; }"), "malformed_string");
    }

    #[test]
    fn unterminated_string_is_rejected() {
        assert_eq!(rule_of(".a { content: \"oops; }"), "malformed_string");
    }

    #[test]
    fn escaped_newline_continues_a_string() {
        let sheet = ok(".a { content: \"one\\\ntwo\"; }");
        assert!(sheet.css.contains("content: \"onetwo\";"), "{}", sheet.css);
    }

    // -- escapes -----------------------------------------------------------

    #[test]
    fn hex_escaped_brace_stays_inside_an_identifier() {
        let sheet = ok(".a\\7D b { color: red; }");
        assert_eq!(sheet.rules, 1);
        assert!(sheet.css.contains(".px-a\\}b"), "{}", sheet.css);
        // Exactly the wrapper's brace pair plus this rule's pair: the escaped
        // brace is emitted as `\}` and never as bare structure.
        assert_eq!(sheet.css.matches('{').count(), 2);
        assert_eq!(sheet.css.matches("\\}").count(), 1);
    }

    #[test]
    fn null_escape_becomes_the_replacement_character() {
        let sheet = ok(".a\\0000 b { color: red; }");
        assert!(sheet.css.contains(".px-a\u{fffd}b"), "{}", sheet.css);
        assert!(!sheet.css.contains('\0'));
    }

    #[test]
    fn literal_null_becomes_the_replacement_character() {
        let sheet = ok(".a\u{0}b { color: red; }");
        assert!(sheet.css.contains(".px-a\u{fffd}b"), "{}", sheet.css);
    }

    #[test]
    fn stray_backslash_is_rejected() {
        assert_eq!(rule_of(".a { color: red }\\\n"), "invalid_escape");
    }

    #[test]
    fn unicode_identifiers_survive_prefixing() {
        let sheet = ok(".日本 { color: red } .ok\u{1f600} { color: blue }");
        assert!(sheet.css.contains(".px-日本"), "{}", sheet.css);
        assert!(sheet.css.contains(".px-ok\u{1f600}"), "{}", sheet.css);
    }

    /// `serialize_ident` round-trips in isolation, but `serialize_token`
    /// concatenates it after the numeric text of a `Dimension` — and there the
    /// claim failed. `1\65 5` tokenizes as `Dimension("1", "e5")` and was
    /// emitted as `1e5`, which re-tokenizes as `Number("1e5")`: a unit
    /// silently swallowed into an exponent.
    #[test]
    fn a_unit_cannot_be_swallowed_into_an_exponent() {
        for (source, fused) in [
            (".a { width: 1\\65 5 }", "1e5"),
            (".a { width: 1\\65 -5 }", "1e-5"),
            (".a { width: 1\\45 5 }", "1E5"),
        ] {
            let sheet = ok(source);
            assert!(
                !sheet.css.contains(fused),
                "{source} fused into {fused}: {}",
                sheet.css
            );
        }
        // Ordinary units are left alone: `em` cannot start an exponent, and a
        // number that already carries one cannot gain a second.
        let sheet = ok(".a { width: 1em; height: 1e5px }");
        assert!(sheet.css.contains("1em"), "{}", sheet.css);
        assert!(sheet.css.contains("1e5px"), "{}", sheet.css);
    }

    // -- comments, CDO/CDC -------------------------------------------------

    #[test]
    fn comments_do_not_nest() {
        let sheet = ok("/* } /* */ .a { color: red }");
        assert_eq!(sheet.rules, 1);
        assert!(!sheet.css.contains("/*"), "{}", sheet.css);
    }

    #[test]
    fn comment_containing_a_brace_is_dropped() {
        let sheet = ok(".a { /* } */ color: red }");
        assert_eq!(sheet.rules, 1);
        assert!(sheet.css.contains("color: red;"), "{}", sheet.css);
    }

    #[test]
    fn unterminated_comment_is_rejected() {
        assert_eq!(rule_of(".a { color: red } /* }"), "unterminated_comment");
    }

    #[test]
    fn cdo_and_cdc_tokens_are_ignored() {
        let sheet = ok("<!-- .a { color: red } -->");
        assert_eq!(sheet.rules, 1);
        assert!(!sheet.css.contains("<!--"), "{}", sheet.css);
        assert!(sheet.css.contains(".px-a {"), "{}", sheet.css);
    }

    // -- token fusion ------------------------------------------------------
    //
    // The three tests above place a comment where its neighbours were already
    // whitespace-separated, so its removal changes nothing and they pass
    // whether or not the emitter reunites the neighbours. The interesting
    // question is never whether the comment survives; it is what its *absence*
    // fuses. Every case below puts the comment between two tokens that were
    // touching, and asserts on the token the fusion would have produced.

    /// The separator must be real in the emitted bytes, not merely implied by
    /// the token list. `serialize_tokens` only spaces tokens where a
    /// `Whitespace` token exists, so a comment that emitted nothing re-glued
    /// what the policy walk had inspected as two tokens.
    #[test]
    fn a_comment_separates_the_tokens_it_sat_between() {
        for (source, fused) in [
            (".a { color: r/**/ed }", "red"),
            (".a { width: 1/**/0px }", "10px"),
            ("#a/**/b { color: red }", "#ab"),
        ] {
            let sheet = ok(source);
            assert!(
                !sheet.css.contains(fused),
                "{source} fused into {fused}: {}",
                sheet.css
            );
        }
    }

    /// Confirmed live in Chromium: `u/**/rl(...)` validated with no `url()`
    /// token for `check_url` to see, then re-emitted as `url(...)` and fired
    /// the request.
    #[test]
    fn a_comment_cannot_forge_a_url_token() {
        for source in [
            ".a { background: u/**/rl(\"https://evil.example/x.png\") }",
            ".a { background: u<!--rl(\"https://evil.example/x.png\") }",
            ".a { background: ur/**/l(\"https://evil.example/x.png\") }",
        ] {
            let sheet = ok(source);
            assert!(
                !sheet.css.contains("url("),
                "{source} forged a url token: {}",
                sheet.css
            );
            // And the emitted sheet must still not forge one when re-validated.
            assert!(!ok(&sheet.css).css.contains("url("), "{}", sheet.css);
        }
    }

    /// Same shape against the bare-string-URL function ban: `image-se/**/t`
    /// was inspected as `image-se` + `t(` and emitted as `image-set(`.
    #[test]
    fn a_comment_cannot_forge_a_forbidden_url_function() {
        for source in [
            ".a { background: image-se/**/t(\"https://evil.example/x.png\" 1x) }",
            ".a { background: image-se<!--t(\"https://evil.example/x.png\" 1x) }",
        ] {
            let sheet = ok(source);
            assert!(
                !sheet.css.contains("image-set("),
                "{source} forged image-set(): {}",
                sheet.css
            );
        }
    }

    /// `@` followed by a comment is `Delim('@')`, so the construct never
    /// reaches `check_at_rule` — it parses as a qualified rule whose prelude is
    /// `[Delim('@'), Ident("keyframes")]`. Each of these was confirmed working
    /// in Chromium: `@keyframes` moved a host element from 200x16 to 7779x622,
    /// `@property` reset a host `z-index` from 60 to `auto`, and `@font-face`
    /// fetched an off-origin font.
    #[test]
    fn a_comment_cannot_forge_an_at_rule() {
        for source in [
            "@/**/keyframes pulse { from { opacity: 0 } to { opacity: 1 } }",
            "@/**/property --z-dialog { syntax: \"*\"; inherits: false; }",
            "@/**/font-face { src: u/**/rl(\"https://evil.example/f.woff2\") }",
            "@/**/import \"https://evil.example/x.css\";",
            "@<!--keyframes pulse { from { opacity: 0 } }",
            "@ keyframes pulse { from { opacity: 0 } }",
            "@media screen { @/**/keyframes pulse { from { opacity: 0 } } }",
        ] {
            assert_eq!(rule_of(source), "masked_at_rule", "{source}");
        }
    }

    /// The forged at-rule is refused on the parse tree, independently of the
    /// separator fix: a selector never legitimately contains a bare `@`, so the
    /// shape is rejected even in sources with no comment in them at all.
    #[test]
    fn a_bare_at_in_a_selector_is_rejected_without_relying_on_the_separator() {
        assert_eq!(
            rule_of("@ keyframes pulse { from { opacity: 0 } }"),
            "masked_at_rule"
        );
        assert_eq!(rule_of("@0keyframes x { color: red }"), "masked_at_rule");
        let failure = rejected("@/**/font-face { color: red }");
        assert_eq!(failure.details["at_rule"], "font-face");
        assert_eq!(failure.code, "css_policy_violation");
    }

    /// A comment between `/` and `*` re-emitted as `1/*2`, which opened a
    /// comment in the *output*. `validate(validate(x))` then failed with
    /// `unterminated_comment`, and Chromium silently swallowed every following
    /// rule.
    #[test]
    fn a_comment_cannot_be_forged_in_the_output() {
        let sheet = ok(".a { z-index: 1//**/*2; }\n.b { color: red }");
        assert!(!sheet.css.contains("/*"), "{}", sheet.css);
        let round_trip = ok(&sheet.css);
        assert!(round_trip.css.contains(".px-px-b"), "{}", round_trip.css);
    }

    // -- forbidden at-rules ------------------------------------------------

    #[test]
    fn global_name_at_rules_are_rejected_at_top_level() {
        for name in FORBIDDEN_AT_RULES {
            let source = format!("@{name} x {{ color: red }}");
            assert_eq!(rule_of(&source), "forbidden_at_rule", "@{name}");
        }
    }

    #[test]
    fn global_name_at_rules_are_rejected_when_nested() {
        for wrapper in [
            "@media screen",
            "@supports (display: grid)",
            "@container (min-width: 10px)",
            "@layer base",
        ] {
            for name in FORBIDDEN_AT_RULES {
                let source = format!("{wrapper} {{ @{name} x {{ color: red }} }}");
                assert_eq!(rule_of(&source), "forbidden_at_rule", "{wrapper} / @{name}");
            }
        }
    }

    #[test]
    fn global_name_at_rules_are_rejected_two_levels_deep() {
        let source = "@layer base { @media screen { @keyframes spin { from { opacity: 0 } } } }";
        assert_eq!(rule_of(source), "forbidden_at_rule");
    }

    #[test]
    fn vendor_prefixed_keyframes_are_rejected() {
        for name in ["-webkit-keyframes", "-MOZ-Keyframes", "-o-keyframes"] {
            let source = format!("@{name} spin {{ from {{ opacity: 0 }} }}");
            assert_eq!(rule_of(&source), "forbidden_at_rule", "@{name}");
        }
    }

    #[test]
    fn at_rule_names_are_matched_case_insensitively_and_through_escapes() {
        assert_eq!(rule_of("@FONT-FACE { src: x }"), "forbidden_at_rule");
        // `\66` is `f`: an escaped at-keyword must not dodge the ban.
        assert_eq!(rule_of("@\\66 ont-face { src: x }"), "forbidden_at_rule");
    }

    #[test]
    fn import_is_rejected_everywhere() {
        for source in [
            "@import url(\"data:text/css,a{}\");",
            "@import \"theme.css\";",
            ".a { color: red } @import \"late.css\";",
            "@media screen { @import \"nested.css\"; }",
            "@layer base { @supports (display: grid) { @import \"deep.css\"; } }",
        ] {
            assert_eq!(rule_of(source), "forbidden_import", "{source}");
        }
    }

    // -- url policy --------------------------------------------------------

    #[test]
    fn data_urls_and_fragments_are_allowed() {
        let sheet = ok(concat!(
            ".a { background: url(\"data:image/gif;base64,R0lGOD\"); }\n",
            ".b { clip-path: url(#clip); }\n",
            ".c { background: url( #frag ); }\n",
            ".d { background: url(data:text/plain,hi); }\n"
        ));
        assert_eq!(sheet.rules, 4);
        assert!(sheet.css.contains("url(\"#clip\")"), "{}", sheet.css);
        assert!(sheet.css.contains("url(\"#frag\")"), "{}", sheet.css);
    }

    #[test]
    fn off_origin_urls_are_rejected() {
        for source in [
            ".a { background: url(https://evil.example/x.png) }",
            ".a { background: url(\"https://evil.example/x.png\") }",
            ".a { background: url('//evil.example/x.png') }",
            ".a { background: url(/local/x.png) }",
            ".a { background: url(x.png) }",
            ".a { background: url(\"HTTPS://evil.example/x.png\") }",
        ] {
            assert_eq!(rule_of(source), "forbidden_url", "{source}");
        }
    }

    /// `check_url` trimmed with Rust's `str::trim`, whose `char::is_whitespace`
    /// is the Unicode definition. None of these are CSS whitespace, no browser
    /// strips them from a URL, and `serialize_string` re-emits them verbatim —
    /// so the validator inspected `data:...` and the browser was handed
    /// `\u{a0}data:...`. Confirmed live: Chromium resolved it relative to the
    /// document and requested `http://127.0.0.1:PORT/__probe`, a same-origin
    /// fetch on an attacker-chosen path.
    #[test]
    fn unicode_whitespace_cannot_disguise_a_url() {
        for lead in [
            '\u{a0}', '\u{85}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}',
            '\u{2004}', '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}',
            '\u{2028}', '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}', '\u{b}', '\u{1c}',
        ] {
            let source = format!(".a {{ background: url(\"{lead}data:x/../../__probe\") }}");
            assert_eq!(rule_of(&source), "forbidden_url", "U+{:04X}", lead as u32);
            let fragment = format!(".a {{ clip-path: url(\"{lead}#clip\") }}");
            assert_eq!(rule_of(&fragment), "forbidden_url", "U+{:04X}", lead as u32);
        }
    }

    /// The backstop, independent of the trim rule: a URL that does not begin
    /// with a scheme letter or `#` cannot be one this policy allows, whatever
    /// the rest of it says.
    #[test]
    fn a_url_must_begin_with_a_scheme_letter_or_a_fragment_marker() {
        for source in [
            ".a { background: url(\"\u{feff}data:text/plain,x\") }",
            ".a { background: url(\"\u{200b}data:text/plain,x\") }",
            ".a { background: url(\"+data:text/plain,x\") }",
            ".a { background: url(\".data:text/plain,x\") }",
        ] {
            assert_eq!(rule_of(source), "forbidden_url", "{source}");
        }
    }

    /// ASCII CSS whitespace is still trimmed, and is genuinely harmless: the
    /// URL parser strips leading and trailing ASCII whitespace itself, so the
    /// string this validator inspected and the one the browser resolves agree.
    #[test]
    fn ascii_whitespace_around_a_url_is_still_trimmed() {
        let sheet = ok(".a { background: url(\" \\09 data:text/plain,x \") }");
        assert_eq!(sheet.rules, 1);
    }

    #[test]
    fn a_paren_inside_a_quoted_url_does_not_end_it() {
        let sheet = ok(".a { background: url(\"data:text/plain,a)b\") no-repeat; }");
        assert_eq!(sheet.rules, 1);
        assert!(
            sheet.css.contains("url(\"data:text/plain,a)b\")"),
            "{}",
            sheet.css
        );
    }

    #[test]
    fn a_paren_inside_a_quoted_url_cannot_hide_an_off_origin_target() {
        assert_eq!(
            rule_of(".a { background: url(\"https://evil.example/a)b\") }"),
            "forbidden_url"
        );
    }

    #[test]
    fn unquoted_url_with_whitespace_is_rejected() {
        assert_eq!(
            rule_of(".a { background: url(data:text/plain,a b) }"),
            "malformed_url"
        );
    }

    #[test]
    fn unterminated_url_is_rejected() {
        assert_eq!(
            rule_of(".a { background: url(data:text/plain,a"),
            "malformed_url"
        );
    }

    #[test]
    fn url_with_a_non_string_argument_is_rejected() {
        assert_eq!(
            rule_of(".a { background: url(\"data:text/plain,a\" \"data:text/plain,b\") }"),
            "malformed_url"
        );
        assert_eq!(rule_of(".a { background: url(  ) }"), "forbidden_url");
    }

    #[test]
    fn string_url_functions_are_rejected() {
        for source in [
            ".a { background: image-set(\"https://evil.example/x.png\" 1x) }",
            ".a { background: -webkit-image-set(\"x.png\" 1x) }",
            ".a { background: src(\"x.png\") }",
        ] {
            assert_eq!(rule_of(source), "forbidden_url_function", "{source}");
        }
    }

    /// `image()` and `-moz-image-rect()` take a bare string URL, which is the
    /// exact shape `image-set()` and `src()` are rejected for: there is no
    /// `url()` token for `check_url` to inspect. Neither is implemented in
    /// Chromium today, so neither fetches yet — which is why a denylist built
    /// from what fetches today missed them.
    #[test]
    fn every_bare_string_url_function_is_rejected() {
        for source in [
            ".a { background: image(\"https://evil.example/x.png\") }",
            ".a { background: IMAGE(\"https://evil.example/x.png\") }",
            ".a { background: -moz-image-rect(\"https://evil.example/x.png\", 0, 1, 1, 0) }",
        ] {
            assert_eq!(rule_of(source), "forbidden_url_function", "{source}");
        }
    }

    /// `element()` paints an arbitrary same-document element as an image. It
    /// fetches nothing, so it is not a URL function, but it reads across the
    /// artifact boundary in the one namespace this module deliberately does
    /// not rewrite: ids (see `id_selector`). Host chrome rendered inside the
    /// artifact is the same disclosure as a screenshot of it.
    #[test]
    fn element_functions_are_rejected() {
        for source in [
            ".a { background: element(#host-sidebar) }",
            ".a { background: -moz-element(#host-sidebar) }",
        ] {
            assert_eq!(rule_of(source), "forbidden_element_function", "{source}");
        }
    }

    // -- class prefixing ---------------------------------------------------

    #[test]
    fn every_selector_shape_is_prefixed() {
        let sheet = ok(concat!(
            ".a.b { color: red }\n",
            ".a .b { color: red }\n",
            ".a > .b { color: red }\n",
            ".a>.b { color: red }\n",
            ".a + .b, .a ~ .b { color: red }\n",
            "div.a:not(.b):is(.c) { color: red }\n",
            "*.a::before { color: red }\n"
        ));
        for expected in [
            ".px-a.px-b {",
            ".px-a .px-b {",
            ".px-a > .px-b {",
            ".px-a>.px-b {",
            ".px-a + .px-b, .px-a ~ .px-b {",
            "div.px-a:not(.px-b):is(.px-c) {",
            "*.px-a::before {",
        ] {
            assert!(
                sheet.css.contains(expected),
                "{expected} missing:\n{}",
                sheet.css
            );
        }
    }

    #[test]
    fn attribute_selectors_and_strings_keep_their_dots() {
        let sheet = ok(concat!(
            "[data-x=a.b] { color: red }\n",
            "[data-x=\".a\"] { color: red }\n",
            "a[href^=\"#x\"].c { color: red }\n",
            ".d { content: \".not-a-selector\"; }\n"
        ));
        assert!(sheet.css.contains("[data-x=a.b] {"), "{}", sheet.css);
        assert!(sheet.css.contains("[data-x=\".a\"] {"), "{}", sheet.css);
        assert!(
            sheet.css.contains("a[href^=\"#x\"].px-c {"),
            "{}",
            sheet.css
        );
        assert!(
            sheet.css.contains("content: \".not-a-selector\";"),
            "{}",
            sheet.css
        );
        assert!(!sheet.css.contains(".px-not-a-selector"), "{}", sheet.css);
        assert!(!sheet.css.contains("a.px-b"), "{}", sheet.css);
    }

    #[test]
    fn decimal_numbers_are_not_class_selectors() {
        let sheet = ok(".a { margin: .5em .25rem; opacity: .5 }");
        assert!(sheet.css.contains("margin: .5em .25rem;"), "{}", sheet.css);
        assert!(!sheet.css.contains("px-5em"), "{}", sheet.css);
    }

    #[test]
    fn nested_rule_selectors_are_prefixed_too() {
        let sheet = ok(".a { color: red; .b { color: blue } &:hover .c { color: green } }");
        assert_eq!(sheet.rules, 3);
        assert!(sheet.css.contains(".px-b {"), "{}", sheet.css);
        assert!(sheet.css.contains("&:hover .px-c {"), "{}", sheet.css);
    }

    #[test]
    fn classes_inside_at_rule_preludes_are_prefixed() {
        let sheet = ok("@scope (.a) to (.b) { .c { color: red } }");
        assert!(
            sheet.css.contains("@scope (.px-a) to (.px-b) {"),
            "{}",
            sheet.css
        );
    }

    #[test]
    fn id_selectors_are_flagged_not_rewritten() {
        let sheet = ok("#toolbar .a { color: red }");
        assert!(sheet.css.contains("#toolbar .px-a {"), "{}", sheet.css);
        assert_eq!(
            sheet.flags,
            vec![Flag {
                rule: "id_selector",
                name: "toolbar".to_owned()
            }]
        );
    }

    #[test]
    fn hex_colours_are_not_id_selectors() {
        let sheet = ok(".a { color: #0f0; background: #ABCDEF }");
        assert!(sheet.css.contains("color: #0f0;"), "{}", sheet.css);
        assert!(sheet.css.contains("background: #ABCDEF;"), "{}", sheet.css);
    }

    // -- declaration versus nested rule ------------------------------------

    #[test]
    fn pseudo_class_nested_rule_is_not_read_as_a_declaration() {
        let sheet = ok(".a { color: red; b:hover { color: blue } }");
        assert_eq!(sheet.rules, 2);
        assert!(sheet.css.contains("b:hover {"), "{}", sheet.css);
        assert!(sheet.css.contains("color: red;"), "{}", sheet.css);
    }

    #[test]
    fn custom_property_may_contain_a_block() {
        let sheet = ok(".a { --x: {color:red}; color: blue }");
        assert_eq!(sheet.rules, 1);
        assert!(sheet.css.contains("--x: {color:red};"), "{}", sheet.css);
        assert!(sheet.css.contains("color: blue;"), "{}", sheet.css);
    }

    #[test]
    fn important_is_preserved() {
        let sheet = ok(".a { color: red !important }");
        assert!(
            sheet.css.contains("color: red !important;"),
            "{}",
            sheet.css
        );
    }

    #[test]
    fn empty_declaration_value_is_rejected() {
        assert_eq!(rule_of(".a { color: ; }"), "invalid_declaration");
    }

    // -- flags -------------------------------------------------------------

    #[test]
    fn unknown_at_rule_is_flagged_not_rejected() {
        let sheet = ok("@wibble { .a { color: red } }");
        assert_eq!(sheet.rules, 2);
        assert!(sheet.css.contains("@wibble {"), "{}", sheet.css);
        assert_eq!(
            sheet.flags,
            vec![Flag {
                rule: "unknown_at_rule",
                name: "wibble".to_owned()
            }]
        );
    }

    #[test]
    fn known_at_rules_are_not_flagged() {
        let sheet = ok(concat!(
            "@media screen { .a { color: red } }\n",
            "@supports (display: grid) { .b { display: grid } }\n",
            "@container (min-width: 10px) { .c { color: red } }\n",
            "@starting-style { .d { opacity: 0 } }\n"
        ));
        assert!(sheet.flags.is_empty(), "{:?}", sheet.flags);
        assert_eq!(sheet.rules, 8);
    }

    /// `@layer` is allowed on purpose and flagged on purpose. Its name is
    /// document-global, like every name on `FORBIDDEN_AT_RULES`, but it is
    /// global *ordering* only, and ordering is bounded by `@scope` confinement
    /// plus the author sheet's load position — **not** by unlayered rules
    /// outranking layers, which is false for `!important`. See the comment in
    /// `check_at_rule`, which carries the full reasoning and the load-order
    /// dependency it rests on. The flag is the record of that decision, and the
    /// tripwire if the host ever layers its own stylesheet.
    #[test]
    fn layer_is_allowed_but_flagged_as_a_global_name() {
        let sheet = ok("@layer base;\n@layer base { .a { color: red } }\n");
        assert!(sheet.css.contains("@layer base;"), "{}", sheet.css);
        assert_eq!(
            sheet.flags,
            vec![Flag {
                rule: "global_layer_name",
                name: "layer".to_owned()
            }]
        );
    }

    /// `@font-feature-values` registers a document-global `@name` and ships in
    /// every engine; its sibling `@font-palette-values` was already banned.
    /// `@color-profile` registers a global `--name` and is the same class.
    #[test]
    fn font_feature_values_and_color_profile_are_banned() {
        assert_eq!(
            rule_of("@font-feature-values Bad { @styleset { nice: 1 } }"),
            "forbidden_at_rule"
        );
        assert_eq!(
            rule_of("@color-profile --bad { src: url(\"data:text/plain,x\") }"),
            "forbidden_at_rule"
        );
        // Nesting inside `@scope` does not scope the registered name.
        assert_eq!(
            rule_of("@scope (.a) { @font-feature-values Bad { @styleset { nice: 1 } } }"),
            "forbidden_at_rule"
        );
    }

    #[test]
    fn unknown_property_is_flagged_not_rejected() {
        let sheet = ok(".a { wibble-thing: 3; -webkit-wibble: 4; --custom: 5; color: red }");
        assert!(sheet.css.contains("wibble-thing: 3;"), "{}", sheet.css);
        assert_eq!(
            sheet.flags,
            vec![
                Flag {
                    rule: "unknown_property",
                    name: "-webkit-wibble".to_owned()
                },
                Flag {
                    rule: "unknown_property",
                    name: "wibble-thing".to_owned()
                },
            ]
        );
    }

    /// Unknown at-rules and unknown properties are flagged so that novelty is
    /// visible. Functions were the asymmetry: anything not on the three-entry
    /// URL denylist produced nothing at all, so a function nobody had thought
    /// about validated with an empty flag list.
    #[test]
    fn unknown_function_is_flagged_not_rejected() {
        let sheet = ok(".a { background: wibble(1) }");
        assert!(sheet.css.contains("wibble(1)"), "{}", sheet.css);
        assert_eq!(
            sheet.flags,
            vec![Flag {
                rule: "unknown_function",
                name: "wibble".to_owned()
            }]
        );
    }

    /// A vendor prefix is novelty in its own right, exactly as it is for
    /// at-rules and properties, so it is flagged under its full name rather
    /// than silently accepted as its unprefixed sibling.
    #[test]
    fn vendor_prefixed_functions_are_flagged_under_their_full_name() {
        let sheet = ok(".a { background: -webkit-linear-gradient(red, blue) }");
        assert_eq!(
            sheet.flags,
            vec![Flag {
                rule: "unknown_function",
                name: "-webkit-linear-gradient".to_owned()
            }]
        );
    }

    /// The flag is only useful if ordinary stylesheets do not trip it. Value
    /// functions and functional pseudo-classes both arrive as `Function`
    /// tokens, so both have to be known.
    #[test]
    fn known_functions_are_not_flagged() {
        let sheet = ok(concat!(
            ".a { color: rgb(1 2 3 / var(--x, 50%)); width: calc(1px + 2em) }\n",
            ".b { background: linear-gradient(red, blue); transform: translate(1px) }\n",
            ".c:not(.d):nth-child(2n + 1) { color: red }\n",
            ".e:is(.f, .g):has(> .h) { color: red }\n",
            ".i { background: url(\"data:text/plain,x\"); filter: blur(2px) }\n",
            "@supports selector(:has(.a)) { .j { color: red } }\n",
            ".k { grid-template-columns: repeat(2, minmax(0, 1fr)) }\n",
            ".l { transition-timing-function: cubic-bezier(0, 0, 1, 1) }\n",
            ".m { color: color-mix(in srgb, red 50%, blue) }\n",
        ));
        assert!(sheet.flags.is_empty(), "{:?}", sheet.flags);
    }

    #[test]
    fn flags_are_deduplicated_and_sorted() {
        let sheet = ok(".a { wibble: 1 } .b { wibble: 2 } @zz { .c { color: red } }");
        assert_eq!(sheet.flags.len(), 2);
        assert_eq!(sheet.flags[0].rule, "unknown_at_rule");
        assert_eq!(sheet.flags[1].rule, "unknown_property");
    }

    // -- limits ------------------------------------------------------------

    #[test]
    fn oversized_source_is_rejected() {
        let source = ".a { color: red }\n".repeat(MAX_SOURCE_BYTES);
        let failure = validate(&source, PREFIX, ROOT, LIMIT).expect_err("too large");
        assert_eq!(failure.code, "css_source_too_large");
        assert_eq!(failure.rule(), Some("source_bytes"));
        assert_eq!(
            failure.details.get("maximum").and_then(Value::as_u64),
            Some(MAX_SOURCE_BYTES as u64)
        );
    }

    #[test]
    fn source_at_the_byte_limit_is_accepted() {
        let unit = ".a{color:red}\n";
        let mut source = unit.repeat(MAX_SOURCE_BYTES / unit.len());
        source.push_str(&" ".repeat(MAX_SOURCE_BYTES - source.len()));
        assert_eq!(source.len(), MAX_SOURCE_BYTES);
        let sheet = validate(&source, PREFIX, ROOT, LIMIT);
        // The byte limit is not the rule limit; this source trips the latter.
        assert_eq!(sheet.expect_err("rule limit").rule(), Some("rule_limit"));
    }

    #[test]
    fn rule_limit_is_enforced() {
        let source = ".a { color: red }\n".repeat(MAX_RULES + 1);
        let failure = validate(&source, PREFIX, ROOT, LIMIT).expect_err("too many rules");
        assert_eq!(failure.code, "css_limit_exceeded");
        assert_eq!(failure.rule(), Some("rule_limit"));
    }

    #[test]
    fn rule_limit_counts_nested_rules() {
        let inner = ".a { color: red }\n".repeat(MAX_RULES);
        let source = format!("@media screen {{\n{inner}}}\n");
        assert_eq!(rule_of(&source), "rule_limit");
    }

    #[test]
    fn exactly_the_rule_limit_is_accepted() {
        let source = ".a { color: red }\n".repeat(MAX_RULES);
        let sheet = ok(&source);
        assert_eq!(sheet.rules, MAX_RULES);
    }

    // -- caller inputs -----------------------------------------------------

    // -- parse depth -------------------------------------------------------

    /// `MAX_RULES` is counted by the post-parse `Walk`, so it cannot bound the
    /// recursion that happens *before* it. Without a parse-time cap, `"a{"`
    /// repeated 32 000 times — 64 000 bytes, inside `MAX_SOURCE_BYTES` — took
    /// the process down with `fatal runtime error: stack overflow, aborting`
    /// (SIGABRT). That is not a panic and `catch_unwind` cannot contain it, so
    /// a single request killed the worker.
    #[test]
    fn parse_depth_is_capped_before_the_stack_is() {
        let source = "a{".repeat(MAX_NESTING_DEPTH + 1);
        assert_eq!(rule_of(&source), "nesting_depth");

        // The real crash payload, at the size that aborted the process.
        let crash = "a{".repeat(32_000);
        assert!(
            crash.len() <= MAX_SOURCE_BYTES,
            "payload must reach the parser"
        );
        assert_eq!(rule_of(&crash), "nesting_depth");

        // At-rule bodies recurse through the same path.
        let at_rules = "@media screen{".repeat(MAX_NESTING_DEPTH + 1);
        assert_eq!(rule_of(&at_rules), "nesting_depth");
    }

    #[test]
    fn exactly_the_nesting_limit_is_accepted() {
        let source = format!(
            "{}color: red{}",
            "a{".repeat(MAX_NESTING_DEPTH),
            "}".repeat(MAX_NESTING_DEPTH)
        );
        let sheet = ok(&source);
        assert_eq!(sheet.rules, MAX_NESTING_DEPTH);
    }

    /// The cap is what makes the *rest* of the recursive machinery safe.
    /// `emit`, `Walk::visit_all` and `Node`'s derived `Drop` all recurse per
    /// level, and a tree that parsed successfully still has to be emitted,
    /// walked and dropped. Because no tree deeper than the cap can be
    /// constructed, none of them needs an iterative rewrite — this test is the
    /// standing check on that reasoning, since it runs the accepted
    /// maximum-depth tree all the way through emission and teardown.
    #[test]
    fn a_maximum_depth_tree_emits_walks_and_drops() {
        let source = format!(
            "{}color: red{}",
            "a{".repeat(MAX_NESTING_DEPTH),
            "}".repeat(MAX_NESTING_DEPTH)
        );
        let sheet = ok(&source);
        assert!(sheet.css.contains("color: red;"), "{}", sheet.css);
        drop(sheet);
    }

    #[test]
    fn nesting_depth_failure_names_its_limit() {
        let failure = rejected(&"a{".repeat(MAX_NESTING_DEPTH + 1));
        assert_eq!(failure.code, "css_limit_exceeded");
        assert_eq!(failure.details["phase"], "parse");
        assert_eq!(failure.details["maximum"], MAX_NESTING_DEPTH as u64);
    }

    #[test]
    fn utf8_bom_is_rejected() {
        let failure = validate("\u{feff}.a { color: red }", PREFIX, ROOT, LIMIT)
            .expect_err("BOM is rejected");
        assert_eq!(failure.rule(), Some("utf8_bom"));
    }

    #[test]
    fn class_prefix_must_be_an_identifier() {
        for prefix in ["", "px-\"}", ".px", "1px", "px }"] {
            let failure = validate(".a { color: red }", prefix, ROOT, LIMIT)
                .expect_err("bad prefix is rejected");
            assert_eq!(failure.rule(), Some("invalid_class_prefix"), "{prefix:?}");
        }
    }

    #[test]
    fn scope_selectors_are_validated_and_reserialised() {
        for root in ["#r) {} .evil { color: red } (#r", "", "@media", "#r)"] {
            let failure = validate(".a { color: red }", PREFIX, root, LIMIT)
                .expect_err("bad scope root is rejected");
            assert_eq!(failure.rule(), Some("invalid_scope_selector"), "{root:?}");
        }
        let failure = validate(".a { color: red }", PREFIX, ROOT, "x { }")
            .expect_err("bad scope limit is rejected");
        assert_eq!(failure.rule(), Some("invalid_scope_selector"));
    }

    #[test]
    fn empty_stylesheet_still_emits_the_wrapper() {
        let sheet = ok("   /* nothing here */  ");
        assert_eq!(sheet.rules, 0);
        assert_eq!(sheet.css, "@scope (#a-root) to (.a-limit) {\n}\n");
    }

    #[test]
    fn failure_details_carry_phase_and_runtime() {
        let failure = rejected("@font-face { src: url(#x) }");
        assert_eq!(failure.code, "css_policy_violation");
        assert_eq!(
            failure.details.get("runtime").and_then(Value::as_str),
            Some(RUNTIME_ID)
        );
        assert_eq!(
            failure.details.get("phase").and_then(Value::as_str),
            Some("policy")
        );
        assert_eq!(
            failure.details.get("at_rule").and_then(Value::as_str),
            Some("font-face")
        );
    }
}
