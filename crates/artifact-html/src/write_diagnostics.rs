//! Tier 1 write-path diagnostics for `native.html.v1`.
//!
//! The HTML write path never looked at authored script: an undefined function
//! (`taskClientNames`) survived a dozen clean write receipts. This module
//! extracts the inline scripts the validator already walks, parses them with
//! the SWC parser the artifact runtime already carries, runs SWC's own scope
//! resolver, and reports findings as **warnings**. Nothing here can reject a
//! write.
//!
//! Findings are positions in the *artifact source body*, not offsets within the
//! extracted script: a person clicks the line the finding names, so the byte
//! offset of the script body in the source is carried onto every span before
//! the line/column is computed. The body offsets come from scanning
//! `<script>...</script>` raw text in source order and matching each against
//! the DOM walk's parsed text, never from re-searching for a fragment (a
//! fragment can match inside a comment, and a CRLF-authored body would not
//! match at all). SWC normalises line endings internally, so a body that
//! contains CRLF is parsed in normalised coordinates and each span is mapped
//! back to raw source bytes before the position is computed.
//!
//! Classic scripts share one global scope, so a name declared at the top level
//! of any executable block is defined in every block. The pass therefore
//! collects top-level declarations across all blocks first and subtracts the
//! union, instead of analysing each block in isolation. That union is
//! **order-insensitive**: a call in an earlier block to a function declared in
//! a later block is not reported, even though it would throw at runtime. This
//! is the right trade for warnings; it is a known gap for promotion to
//! rejection.
//!
//! The identifier subtraction is a browser-globals allowlist vendored from the
//! `globals` npm package (`globals_browser.json`) plus its `es2021` builtins
//! (`globals_es2021.json`), plus the runtime bridge name `nativeArtifact`,
//! element `id` values (browser named access), and cross-block top-level
//! declarations. A missing entry here is a false positive, which is a bug: see
//! the corpus in the pull request.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use serde::Serialize;
use swc_common::{sync::Lrc, FileName, Globals, Mark, SourceMap, GLOBALS};
use swc_ecma_ast::{
    AssignTarget, CallExpr, Callee, Expr, Ident, Lit, MemberExpr, MemberProp, ObjectLit, Pat, Prop,
    PropName, PropOrSpread, Script, SimpleAssignTarget, UnaryExpr, UnaryOp, WithStmt,
};
use swc_ecma_parser::{lexer::Lexer, EsSyntax, Parser, StringInput, Syntax};
use swc_ecma_transforms_base::resolver;
use swc_ecma_visit::{Visit, VisitMutWith, VisitWith};

pub const WRITE_DIAGNOSTIC_FORMAT: &str = "native.artifact-write-diagnostic.v1";
/// The runtime diagnostics path caps at 100; the same bound applies here so a
/// pathological body cannot produce unbounded write/render output.
pub const WRITE_DIAGNOSTIC_LIMIT: usize = 100;

pub const UNDEFINED_IDENTIFIER: &str = "html_undefined_identifier";
pub const UNKNOWN_INTERACTION_ENTRY: &str = "html_unknown_interaction_entry";
pub const UNKNOWN_INPUT_PORT: &str = "html_unknown_input_port";

const BROWSER_GLOBALS: &str = include_str!("globals_browser.json");
const ES2021_GLOBALS: &str = include_str!("globals_es2021.json");

/// Standard `Object`/`Map`/`Set` prototype members. Reading one off the port
/// map is not a port read, so the port rule must not call it an unknown port.
/// The trade is explicit: a declared port that shares one of these names is
/// still fine (it is declared, so the rule would not fire anyway), while an
/// undeclared read of one of these names is not reported.
const PORT_MAP_PROTOTYPE_MEMBERS: &[&str] = &[
    "add",
    "clear",
    "constructor",
    "delete",
    "entries",
    "forEach",
    "get",
    "has",
    "hasOwnProperty",
    "isPrototypeOf",
    "keys",
    "propertyIsEnumerable",
    "set",
    "size",
    "toLocaleString",
    "toString",
    "valueOf",
    "values",
];

#[cfg(test)]
pub(crate) mod test_probe {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    /// Per-body-digest count of times the write-diagnostics pass ran, so a test
    /// can prove `validate_cached` runs it once per distinct source.
    fn runs() -> &'static Mutex<HashMap<String, usize>> {
        static RUNS: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();
        RUNS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    pub(crate) fn note(digest: &str) {
        let mut runs = runs().lock().expect("diagnostics pass probe poisoned");
        *runs.entry(digest.to_owned()).or_insert(0) += 1;
    }

    pub(crate) fn runs_for(digest: &str) -> usize {
        runs()
            .lock()
            .expect("diagnostics pass probe poisoned")
            .get(digest)
            .copied()
            .unwrap_or(0)
    }
}

/// One inline `<script>` the validator's DOM walk saw, in document order.
///
/// `text` is the parsed script body (HTML raw text, so identical to the source
/// bytes except newline normalisation); `executable` is false for non-JS
/// `type` attributes and the inert JSON manifest, whose contents a browser
/// never runs. Non-executable blocks are still listed so the raw-source scan
/// can pair bodies by document order.
#[derive(Clone, Debug)]
pub struct ScriptElement {
    pub text: String,
    pub executable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WriteDiagnostic {
    pub format: &'static str,
    pub code: &'static str,
    pub severity: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub line: usize,
    pub column: usize,
}

/// Severity is a fixed function of the code, never a per-finding judgement.
/// Step 4 flips one arm to rejection; that must stay a one-line change.
fn severity_for(_code: &str) -> &'static str {
    match _code {
        UNDEFINED_IDENTIFIER | UNKNOWN_INTERACTION_ENTRY | UNKNOWN_INPUT_PORT => "warning",
        _ => "warning",
    }
}

impl WriteDiagnostic {
    fn new(
        code: &'static str,
        message: String,
        name: Option<String>,
        line: usize,
        column: usize,
    ) -> Self {
        Self {
            format: WRITE_DIAGNOSTIC_FORMAT,
            code,
            severity: severity_for(code),
            message,
            name,
            line,
            column,
        }
    }
}

fn allowlist() -> &'static BTreeSet<String> {
    static ALLOWLIST: OnceLock<BTreeSet<String>> = OnceLock::new();
    ALLOWLIST.get_or_init(|| {
        let mut names = BTreeSet::new();
        for raw in [BROWSER_GLOBALS, ES2021_GLOBALS] {
            match serde_json::from_str::<Vec<String>>(raw) {
                Ok(values) => names.extend(values),
                Err(error) => {
                    // A malformed vendored allowlist would make every builtin a
                    // false positive; fail loudly in tests rather than silently.
                    debug_assert!(false, "vendored globals allowlist is malformed: {error}");
                }
            }
        }
        names.insert("nativeArtifact".into());
        // Implicit inside every non-arrow function; not in the es2021 set.
        names.insert("arguments".into());
        names
    })
}

fn unparen(expr: &Expr) -> &Expr {
    let mut current = expr;
    loop {
        current = match current {
            Expr::Paren(paren) => &paren.expr,
            _ => return current,
        };
    }
}

fn ident_of(expr: &Expr) -> Option<&Ident> {
    match unparen(expr) {
        Expr::Ident(ident) => Some(ident),
        _ => None,
    }
}

fn prop_name(prop: &MemberProp) -> Option<String> {
    match prop {
        MemberProp::Ident(name) => Some(name.sym.to_string()),
        MemberProp::Computed(computed) => match unparen(&computed.expr) {
            Expr::Lit(Lit::Str(value)) => Some(value.value.to_string()),
            _ => None,
        },
        MemberProp::PrivateName(_) => None,
    }
}

fn static_name(name: &PropName) -> Option<String> {
    match name {
        PropName::Ident(ident) => Some(ident.sym.to_string()),
        PropName::Str(value) => Some(value.value.to_string()),
        _ => None,
    }
}

/// `X.input.inputs` for any chain root `X`.
fn is_port_map_chain(expr: &Expr) -> bool {
    let Expr::Member(outer) = unparen(expr) else {
        return false;
    };
    if prop_name(&outer.prop).as_deref() != Some("inputs") {
        return false;
    }
    let Expr::Member(inner) = unparen(&outer.obj) else {
        return false;
    };
    prop_name(&inner.prop).as_deref() == Some("input")
}

/// `<bundle>.inputs` where `<bundle>` is a tracked alias of `*.input`.
fn is_bundle_inputs(expr: &Expr, bundles: &BTreeSet<String>) -> bool {
    let Expr::Member(member) = unparen(expr) else {
        return false;
    };
    if prop_name(&member.prop).as_deref() != Some("inputs") {
        return false;
    }
    ident_of(&member.obj).is_some_and(|ident| bundles.contains(ident.sym.as_ref()))
}

fn is_bundle(expr: &Expr) -> bool {
    let Expr::Member(member) = unparen(expr) else {
        return false;
    };
    prop_name(&member.prop).as_deref() == Some("input")
}

/// The host-injected bridge is a bare `nativeArtifact` global, reached through
/// `window`/`globalThis`/`self`, or a tracked local alias. It is deliberately
/// not "any receiver with a `nativeArtifact` property": `o.nativeArtifact` is
/// somebody else's object, not the bridge.
fn is_native_bridge(expr: &Expr) -> bool {
    match unparen(expr) {
        Expr::Ident(ident) => ident.sym.as_ref() == "nativeArtifact",
        Expr::Member(member) => {
            prop_name(&member.prop).as_deref() == Some("nativeArtifact")
                && ident_of(&member.obj).is_some_and(|object| {
                    matches!(object.sym.as_ref(), "window" | "globalThis" | "self")
                })
        }
        _ => false,
    }
}

/// Pass 1: alias sets.
///
/// `port_maps`/`bridges` record names whose write *could* be the port map or a
/// bridge alias; `reassigned` records names written from something else. A name
/// in both is disqualified, so a variable that is later reused for a plain
/// object cannot manufacture a finding.
#[derive(Default)]
struct AliasCollector {
    port_maps: BTreeSet<String>,
    bundles: BTreeSet<String>,
    bridges: BTreeSet<String>,
    reassigned: BTreeSet<String>,
}

impl AliasCollector {
    fn classify(&mut self, name: String, value: &Expr) {
        if is_port_map_chain(value) || is_bundle_inputs(value, &self.bundles) {
            self.port_maps.insert(name);
        } else if is_bundle(value) {
            self.bundles.insert(name);
        } else if is_native_bridge(value) {
            self.bridges.insert(name);
        } else {
            self.reassigned.insert(name);
        }
    }

    fn note_write(&mut self, target: &AssignTarget, value: &Expr) {
        let AssignTarget::Simple(SimpleAssignTarget::Ident(binding)) = target else {
            return;
        };
        let name = binding.id.sym.to_string();
        self.classify(name, value);
    }

    /// Effective port-map aliases: written as the port map and never written
    /// from anything else.
    fn effective_port_maps(&self) -> BTreeSet<String> {
        self.port_maps
            .difference(&self.reassigned)
            .cloned()
            .collect()
    }

    /// Effective bridge aliases, same ratchet.
    fn effective_bridges(&self) -> BTreeSet<String> {
        self.bridges.difference(&self.reassigned).cloned().collect()
    }
}

impl Visit for AliasCollector {
    fn visit_var_declarator(&mut self, declarator: &swc_ecma_ast::VarDeclarator) {
        if let (Pat::Ident(binding), Some(init)) = (&declarator.name, &declarator.init) {
            self.classify(binding.id.sym.to_string(), init);
        }
        declarator.visit_children_with(self);
    }

    fn visit_assign_expr(&mut self, assign: &swc_ecma_ast::AssignExpr) {
        if assign.op == swc_ecma_ast::AssignOp::Assign {
            self.note_write(&assign.left, &assign.right);
        }
        assign.visit_children_with(self);
    }
}

/// Pass 2: findings.
struct FindingCollector<'a> {
    body: &'a NormalizedBody,
    source: &'a str,
    ports: &'a BTreeSet<String>,
    interactions: &'a BTreeSet<String>,
    port_maps: &'a BTreeSet<String>,
    bundles: &'a BTreeSet<String>,
    bridges: &'a BTreeSet<String>,
    limit: usize,
    findings: Vec<WriteDiagnostic>,
}

impl<'a> FindingCollector<'a> {
    fn at(&self, local: usize) -> (usize, usize) {
        crate::html::source_position(self.source, self.body.absolute(local))
    }

    fn push(&mut self, code: &'static str, message: String, name: String, local: usize) {
        if self.findings.len() >= self.limit {
            return;
        }
        let (line, column) = self.at(local);
        self.findings.push(WriteDiagnostic::new(
            code,
            message,
            Some(name),
            line,
            column,
        ));
    }
}

impl Visit for FindingCollector<'_> {
    fn visit_member_expr(&mut self, member: &MemberExpr) {
        if let Some(name) = prop_name(&member.prop) {
            let object = unparen(&member.obj);
            let port_map = is_port_map_chain(object)
                || is_bundle_inputs(object, self.bundles)
                || ident_of(object)
                    .is_some_and(|ident| self.port_maps.contains(ident.sym.as_ref()));
            if port_map
                && !self.ports.contains(&name)
                && !PORT_MAP_PROTOTYPE_MEMBERS.contains(&name.as_str())
            {
                let local = member.span.lo.0.saturating_sub(1) as usize;
                self.push(
                    UNKNOWN_INPUT_PORT,
                    format!("No input port named `{name}` is bound"),
                    name,
                    local,
                );
            }
        }
        member.visit_children_with(self);
    }

    fn visit_call_expr(&mut self, call: &CallExpr) {
        if let Callee::Expr(callee) = &call.callee {
            if let Expr::Member(member) = unparen(callee) {
                if prop_name(&member.prop).as_deref() == Some("propose")
                    && bridge_callee(unparen(&member.obj), self.bridges)
                {
                    if let Some(argument) = call.args.first().filter(|arg| arg.spread.is_none()) {
                        self.check_entry_id(&argument.expr);
                    }
                }
            }
        }
        call.visit_children_with(self);
    }
}

impl FindingCollector<'_> {
    fn check_entry_id(&mut self, argument: &Expr) {
        let Expr::Object(ObjectLit { props, .. }) = unparen(argument) else {
            return;
        };
        for prop in props {
            let PropOrSpread::Prop(prop) = prop else {
                continue;
            };
            let Prop::KeyValue(entry) = prop.as_ref() else {
                continue;
            };
            if static_name(&entry.key).as_deref() != Some("entry_id") {
                continue;
            }
            let Expr::Lit(Lit::Str(value)) = unparen(&entry.value) else {
                continue;
            };
            let id = value.value.to_string();
            if !self.interactions.contains(&id) {
                let local = value.span.lo.0.saturating_sub(1) as usize;
                self.push(
                    UNKNOWN_INTERACTION_ENTRY,
                    format!("No interaction entry named `{id}` is declared in this document"),
                    id,
                    local,
                );
            }
        }
    }
}

fn bridge_callee(expr: &Expr, bridges: &BTreeSet<String>) -> bool {
    is_native_bridge(expr)
        || ident_of(expr).is_some_and(|ident| bridges.contains(ident.sym.as_ref()))
}

#[derive(Default)]
struct WithDetector {
    found: bool,
}

impl Visit for WithDetector {
    fn visit_with_stmt(&mut self, _: &WithStmt) {
        self.found = true;
    }
}

#[derive(Default)]
struct TopLevelCollector {
    mark: Option<Mark>,
    names: BTreeSet<String>,
}

impl Visit for TopLevelCollector {
    fn visit_ident(&mut self, ident: &Ident) {
        if let Some(mark) = self.mark {
            if ident.ctxt.outer() == mark {
                self.names.insert(ident.sym.to_string());
            }
        }
    }
}

struct UnresolvedCollector<'a> {
    mark: Mark,
    allowed: &'a BTreeSet<String>,
    cross_script: &'a BTreeSet<String>,
    document_names: &'a BTreeSet<String>,
    found: Vec<(String, usize)>,
}

impl Visit for UnresolvedCollector<'_> {
    fn visit_unary_expr(&mut self, expr: &UnaryExpr) {
        // `typeof undeclared` is legal and is the idiom for probing an optional
        // global; the direct operand is not a finding. `typeof a.b` still is:
        // reading a property off an undeclared base throws.
        if expr.op == UnaryOp::TypeOf && matches!(unparen(&expr.arg), Expr::Ident(_)) {
            return;
        }
        expr.visit_children_with(self);
    }

    fn visit_ident(&mut self, ident: &Ident) {
        if ident.ctxt.outer() != self.mark {
            return;
        }
        let name = ident.sym.to_string();
        if self.allowed.contains(&name)
            || self.cross_script.contains(&name)
            || self.document_names.contains(&name)
        {
            return;
        }
        self.found
            .push((name, ident.span.lo.0.saturating_sub(1) as usize));
    }
}

/// A `<script>` body normalised the way the parser sees it, plus the map back
/// to raw source byte offsets.
///
/// SWC normalises `\r\n` and lone `\r` to `\n` before lexing, so a span offset
/// is a byte index into the normalised text. `offsets[i]` is the raw byte
/// index of normalised byte `i`, which is what a source-body position needs.
struct NormalizedBody {
    text: String,
    offsets: Vec<usize>,
    /// Raw byte length of the body; the offset just past the last byte.
    raw_len: usize,
    /// Raw byte offset of the body start in the artifact source.
    start: usize,
}

impl NormalizedBody {
    fn absolute(&self, local: usize) -> usize {
        if local >= self.offsets.len() {
            return self.start + self.raw_len;
        }
        self.start + self.offsets[local]
    }
}

fn normalize_body(raw: &str) -> NormalizedBody {
    let mut text = String::with_capacity(raw.len());
    let mut offsets = Vec::with_capacity(raw.len());
    let mut chars = raw.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        if ch == '\r' {
            if matches!(chars.peek(), Some((_, '\n'))) {
                chars.next();
            }
            text.push('\n');
            offsets.push(index);
        } else {
            let mut buffer = [0u8; 4];
            let encoded = ch.encode_utf8(&mut buffer);
            for _ in 0..encoded.len() {
                offsets.push(index);
            }
            text.push(ch);
        }
    }
    NormalizedBody {
        text,
        offsets,
        raw_len: raw.len(),
        start: 0,
    }
}

struct ResolvedScript {
    ast: Script,
    unresolved_mark: Mark,
    top_level_mark: Mark,
}

fn resolve_script(text: &str) -> Option<ResolvedScript> {
    let cm: Lrc<SourceMap> = Default::default();
    let file = cm.new_source_file(
        FileName::Custom("native.html.v1.inline".into()).into(),
        text.to_owned(),
    );
    let lexer = Lexer::new(
        Syntax::Es(EsSyntax::default()),
        Default::default(),
        StringInput::from(&*file),
        None,
    );
    let mut parser = Parser::new_from(lexer);
    let mut ast: Script = parser.parse_script().ok()?;
    // Recoverable errors leave spans unreliable; a warning with a wrong line is
    // worse than no warning, so skip a script the parser only partially
    // understood. This pass never rejects a write for syntax.
    if !parser.take_errors().is_empty() {
        return None;
    }
    let unresolved_mark = Mark::new();
    let top_level_mark = Mark::new();
    ast.visit_mut_with(&mut resolver(unresolved_mark, top_level_mark, false));
    Some(ResolvedScript {
        ast,
        unresolved_mark,
        top_level_mark,
    })
}

#[allow(clippy::too_many_arguments)]
fn collect_script_findings(
    source: &str,
    body: &NormalizedBody,
    resolved: &ResolvedScript,
    allowed: &BTreeSet<String>,
    cross_script: &BTreeSet<String>,
    document_names: &BTreeSet<String>,
    ports: &BTreeSet<String>,
    interactions: &BTreeSet<String>,
    limit: usize,
    findings: &mut Vec<WriteDiagnostic>,
) {
    if findings.len() >= limit {
        return;
    }
    let mut detector = WithDetector::default();
    resolved.ast.visit_with(&mut detector);
    // `with` makes static scope analysis unsound (any bare name may come from
    // the object), so a script that uses it gets no undefined-identifier
    // findings rather than a stream of false positives.
    if !detector.found {
        let mut unresolved = UnresolvedCollector {
            mark: resolved.unresolved_mark,
            allowed,
            cross_script,
            document_names,
            found: Vec::new(),
        };
        resolved.ast.visit_with(&mut unresolved);
        for (name, local) in unresolved.found {
            let (line, column) = crate::html::source_position(source, body.absolute(local));
            findings.push(WriteDiagnostic::new(
                UNDEFINED_IDENTIFIER,
                format!("`{name}` is not defined in this document"),
                Some(name),
                line,
                column,
            ));
            if findings.len() >= limit {
                return;
            }
        }
    }

    let mut aliases = AliasCollector::default();
    resolved.ast.visit_with(&mut aliases);
    let port_maps = aliases.effective_port_maps();
    let bridges = aliases.effective_bridges();
    let bundles = aliases.bundles;
    let mut collector = FindingCollector {
        body,
        source,
        ports,
        interactions,
        port_maps: &port_maps,
        bundles: &bundles,
        bridges: &bridges,
        limit,
        findings: Vec::new(),
    };
    resolved.ast.visit_with(&mut collector);
    findings.extend(collector.findings);
}

/// Byte ranges of every `<script>...</script>` raw-text body, in source order.
///
/// This mirrors the HTML parser's raw-text rule (the body ends at the first
/// case-insensitive `</script`). It is a byte scan, not an HTML parse, so it
/// also finds a `<script>` written inside an HTML comment. That is handled in
/// pairing: ranges are consumed in document order, and when several carry the
/// same text the caller prefers one whose body does not start inside a comment,
/// so a commented-out copy cannot donate its offsets to the live script after
/// it. The guarantee is about which candidate is chosen for a matching DOM
/// script — the scan itself does not skip comments.
fn raw_inline_script_bodies(source: &str) -> Vec<(usize, usize)> {
    let lower = source.to_ascii_lowercase();
    let mut bodies = Vec::new();
    let mut cursor = 0usize;
    while let Some(relative) = lower[cursor..].find("<script") {
        let tag_start = cursor + relative;
        let after_name = tag_start + "<script".len();
        match source.as_bytes().get(after_name) {
            Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r') | Some(b'>') | Some(b'/') => {}
            _ => {
                cursor = after_name;
                continue;
            }
        }
        let Some(tag_end) = crate::html::tag_end(source, after_name) else {
            break;
        };
        let Some(close_relative) = lower[tag_end..].find("</script") else {
            break;
        };
        let close = tag_end + close_relative;
        bodies.push((tag_end, close));
        cursor = close + "</script".len();
    }
    bodies
}

/// Whether the raw body at `index` begins inside an HTML comment.
///
/// Only the gap since the previous body is examined, which is sufficient: a
/// comment containing a `<script>` lies wholly in that gap. HTML comments do
/// not nest, so a simple `<!--`/`-->` toggle is exact enough for this check.
fn body_starts_in_comment(source: &str, bodies: &[(usize, usize)], index: usize) -> bool {
    let end = bodies[index].0;
    let start = if index == 0 { 0 } else { bodies[index - 1].1 };
    let bytes = source.as_bytes();
    let mut in_comment = false;
    let mut cursor = start;
    while cursor < end {
        if !in_comment && bytes[cursor..end].starts_with(b"<!--") {
            in_comment = true;
            cursor += 4;
        } else if in_comment && bytes[cursor..end].starts_with(b"-->") {
            in_comment = false;
            cursor += 3;
        } else {
            cursor += 1;
        }
    }
    in_comment
}

/// One finding per occurrence, ordered by position then code then name, capped
/// at [`WRITE_DIAGNOSTIC_LIMIT`] so a pathological body cannot unbounded-output.
pub fn html_write_diagnostics(
    source: &str,
    scripts: &[ScriptElement],
    ports: &[String],
    interactions: &[String],
    document_ids: &[String],
) -> Vec<WriteDiagnostic> {
    // No executable block means no SWC work at all: the fast path for an
    // artifact with no script.
    if !scripts.iter().any(|script| script.executable) {
        return Vec::new();
    }
    let port_names: BTreeSet<String> = ports.iter().cloned().collect();
    let entry_names: BTreeSet<String> = interactions.iter().cloned().collect();
    let document_names: BTreeSet<String> = document_ids.iter().cloned().collect();
    let mut findings = Vec::new();
    let globals = Globals::new();
    GLOBALS.set(&globals, || {
        let bodies = raw_inline_script_bodies(source);
        let mut body_cursor = 0usize;
        let mut resolved: Vec<(NormalizedBody, ResolvedScript)> = Vec::new();
        for script in scripts {
            // Consume the run of consecutive raw bodies whose normalised text
            // matches this DOM script. Bodies that do not match before the run
            // are skipped; the run is left intact for later DOM scripts except
            // for the one chosen here.
            let mut run: Vec<usize> = Vec::new();
            let mut scan = body_cursor;
            while scan < bodies.len() {
                let (start, end) = bodies[scan];
                if normalize_body(&source[start..end]).text == script.text {
                    run.push(scan);
                    scan += 1;
                } else if run.is_empty() {
                    scan += 1;
                } else {
                    break;
                }
            }
            // Prefer a body that does not start inside an HTML comment. A
            // commented-out `<script>` with byte-identical text would otherwise
            // donate its offsets to the live script that follows it.
            let chosen = run
                .iter()
                .copied()
                .find(|index| !body_starts_in_comment(source, &bodies, *index))
                .or_else(|| run.first().copied());
            let Some(chosen) = chosen else {
                continue;
            };
            body_cursor = chosen + 1;
            let (start, end) = bodies[chosen];
            let mut body = normalize_body(&source[start..end]);
            body.start = start;
            if !script.executable || body.text.is_empty() {
                continue;
            }
            if let Some(entry) = resolve_script(&body.text) {
                resolved.push((body, entry));
            }
        }
        let mut cross_script: BTreeSet<String> = BTreeSet::new();
        for (_, entry) in &resolved {
            let mut collector = TopLevelCollector {
                mark: Some(entry.top_level_mark),
                names: BTreeSet::new(),
            };
            entry.ast.visit_with(&mut collector);
            cross_script.extend(collector.names);
        }
        let allowed = allowlist();
        for (body, entry) in &resolved {
            collect_script_findings(
                source,
                body,
                entry,
                allowed,
                &cross_script,
                &document_names,
                &port_names,
                &entry_names,
                WRITE_DIAGNOSTIC_LIMIT,
                &mut findings,
            );
            if findings.len() >= WRITE_DIAGNOSTIC_LIMIT {
                break;
            }
        }
    });
    findings.sort_by(|left, right| {
        (left.line, left.column, left.code, left.name.as_deref()).cmp(&(
            right.line,
            right.column,
            right.code,
            right.name.as_deref(),
        ))
    });
    findings.truncate(WRITE_DIAGNOSTIC_LIMIT);
    findings
}

/// True when a `<script type=...>` value denotes JavaScript a browser executes.
pub fn executable_script_type(raw: Option<&str>) -> bool {
    match raw.map(str::trim) {
        None | Some("") => true,
        Some(value) => matches!(
            value.to_ascii_lowercase().as_str(),
            "text/javascript"
                | "application/javascript"
                | "text/ecmascript"
                | "application/ecmascript"
                | "module"
        ),
    }
}
