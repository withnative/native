//! Native pre-parse stack guard. No generated parser or recursive AST work runs here.
//!
//! A segment sums unary, arithmetic/relation and postfix edges. Bracket children
//! inherit that sum; their maximum height is retained on close (including grouping,
//! whose parse tree recurses even though its AST node disappears). Logical rules
//! are flat in ANTLR and balanced by the visitor, so they cost logarithms instead
//! of a whole-expression operator total. Ternary else levels survive ':' and logical
//! resets. Commas end an expression only inside argument/initializer lists.
use super::{gen, ParseError, ParseErrors};
use crate::common::ast::SourceInfo;
use antlr4rust::error_listener::ErrorListener;
use antlr4rust::errors::ANTLRError;
use antlr4rust::recognizer::Recognizer;
use antlr4rust::token::{Token, TOKEN_EOF};
use antlr4rust::token_factory::TokenFactory;
use antlr4rust::{InputStream, TokenSource};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

// Native caps are calibrated by isolated debug AND release probes below.
// The proof covers parsing, visiting and ordinary drop on 4 MiB and 8 MiB stacks.
pub(crate) const MAX_SOURCE_BYTES: usize = 16 * 1024;
pub(crate) const MAX_PARSE_TOKENS: usize = 2048;
pub(crate) const MAX_PARSE_DEPTH: usize = 96;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct L0Measures {
    pub(crate) bytes: usize,
    pub(crate) real_tokens: usize,
    /// Conservative grammar/visitor chain height, NOT exact expanded AST depth.
    pub(crate) max_frame_chain: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Root,
    Group,
    Call,
    Index,
    List,
    Map,
}

struct Frame {
    kind: Kind,
    base: usize,
    segment: usize,
    persistent: usize,
    pending_questions: usize,
    peak: usize,
    completed: usize,
    ands: usize,
    ors: usize,
}

impl Frame {
    fn new(kind: Kind, base: usize) -> Self {
        Self {
            kind,
            base,
            segment: 0,
            persistent: 0,
            pending_questions: 0,
            peak: 0,
            completed: 0,
            ands: 0,
            ors: 0,
        }
    }
    fn height(&self) -> usize {
        self.completed.max(
            self.peak.max(self.segment + self.persistent)
                + ceil_log2(self.ands + 1)
                + ceil_log2(self.ors + 1),
        )
    }
    fn finish_expression(&mut self) {
        self.completed = self.height();
        self.segment = 0;
        self.persistent = 0;
        self.pending_questions = 0;
        self.peak = 0;
        self.ands = 0;
        self.ors = 0;
    }
    fn reset_segment(&mut self) {
        self.peak = self.peak.max(self.segment + self.persistent);
        self.segment = 0;
    }
}

fn ceil_log2(n: usize) -> usize {
    if n <= 1 {
        0
    } else {
        (usize::BITS - (n - 1).leading_zeros()) as usize
    }
}

fn error(source: &str, pos: (isize, isize), msg: String) -> ParseErrors {
    let mut info = SourceInfo::default();
    // Keep diagnostics bounded even when the byte guard sees a giant input.
    info.source = source[..source.floor_char_boundary(MAX_SOURCE_BYTES)].into();
    ParseErrors {
        errors: vec![ParseError {
            source: None,
            pos,
            msg,
            expr_id: 0,
            source_info: Some(Arc::new(info)),
        }],
    }
}

fn limit_error(
    source: &str,
    pos: (isize, isize),
    span: (isize, isize),
    what: &str,
    measured: usize,
    limit: usize,
) -> ParseErrors {
    error(
        source,
        pos,
        format!(
            "input too large: L0 {what} {measured} exceeds limit {limit} \
        at character span {}..{}; split the expression across clauses or shorten the chain",
            span.0, span.1
        ),
    )
}

struct LexErrors(Rc<RefCell<Vec<(isize, isize, String)>>>);
impl<'a, T: Recognizer<'a>> ErrorListener<'a, T> for LexErrors {
    fn syntax_error(
        &self,
        _: &T,
        _: Option<&<T::TF as TokenFactory<'a>>::Inner>,
        line: isize,
        column: isize,
        msg: &str,
        _: Option<&ANTLRError>,
    ) {
        self.0.borrow_mut().push((line, column + 1, msg.into()));
    }
}

pub(crate) fn check(source: &str) -> Result<L0Measures, ParseErrors> {
    measure(source, MAX_SOURCE_BYTES, MAX_PARSE_TOKENS, MAX_PARSE_DEPTH)
}

pub(super) fn check_with_caps(
    source: &str,
    bytes: usize,
    tokens: usize,
) -> Result<L0Measures, ParseErrors> {
    if bytes >= MAX_SOURCE_BYTES && tokens >= MAX_PARSE_TOKENS {
        check(source)
    } else {
        measure(
            source,
            bytes.min(MAX_SOURCE_BYTES),
            tokens.min(MAX_PARSE_TOKENS),
            MAX_PARSE_DEPTH,
        )
    }
}

// Arbitrary candidates are private to this module and its tests; callers cannot
// bypass the production guard or expose an arbitrary-limits public API.
fn measure(
    source: &str,
    byte_limit: usize,
    token_limit: usize,
    chain_limit: usize,
) -> Result<L0Measures, ParseErrors> {
    if source.len() > byte_limit {
        let prefix = &source[..source.floor_char_boundary(byte_limit)];
        let line = prefix.bytes().filter(|&c| c == b'\n').count() as isize + 1;
        let col = prefix.rsplit('\n').next().unwrap_or("").chars().count() as isize + 1;
        let offset = prefix.chars().count() as isize;
        return Err(limit_error(
            source,
            (line, col),
            (offset, offset + 1),
            "source bytes",
            source.len(),
            byte_limit,
        ));
    }
    let lex_errors = Rc::new(RefCell::new(Vec::new()));
    let mut lexer = gen::CELLexer::new(InputStream::new(source));
    lexer.remove_error_listeners();
    lexer.add_error_listener(Box::new(LexErrors(lex_errors.clone())));
    let mut measures = L0Measures {
        bytes: source.len(),
        ..Default::default()
    };
    let mut frames = vec![Frame::new(Kind::Root, 0)];
    let mut operand = true;
    let mut previous = TOKEN_EOF;
    let mut macro_allowance = 0;
    loop {
        let token = lexer.next_token();
        // Lexer recovery discards bad characters. Never let the resulting token
        // stream justify entry into recursive parsing after such a discard.
        if let Some((line, col, msg)) = lex_errors.borrow().first() {
            return Err(error(
                source,
                (*line, *col),
                format!("Syntax error: {msg}; correct the invalid token before parsing"),
            ));
        }
        let ty = token.get_token_type();
        if ty == TOKEN_EOF {
            break;
        }
        if token.get_channel() != 0 {
            continue;
        }
        let pos = (token.get_line(), token.get_column() + 1);
        let span = (token.get_start(), token.get_stop() + 1);
        measures.real_tokens += 1;
        if measures.real_tokens > token_limit {
            return Err(limit_error(
                source,
                pos,
                span,
                "tokens",
                measures.real_tokens,
                token_limit,
            ));
        }
        let frame = frames.last_mut().unwrap();
        match ty {
            gen::LPAREN | gen::LBRACKET | gen::LBRACE => {
                let kind = match ty {
                    gen::LPAREN if !operand => Kind::Call,
                    gen::LPAREN => Kind::Group,
                    gen::LBRACKET if !operand => Kind::Index,
                    gen::LBRACKET => Kind::List,
                    _ => Kind::Map,
                };
                // Bracket entry costs two units: a complete recursive grammar
                // descent plus its child/initializer context. This native weight
                // is calibrated by the debug/release probes, not an AST measure.
                // Receiver '.' already costs an edge. Macro expansion adds at
                // most four AST levels below its call.
                frame.segment += 2 + if kind == Kind::Call {
                    macro_allowance
                } else {
                    0
                };
                let base = frame.base + frame.segment + frame.persistent;
                frames.push(Frame::new(kind, base));
                operand = true;
            }
            gen::RPAREN | gen::RPRACKET | gen::RBRACE => {
                let matches = match ty {
                    gen::RPAREN => matches!(frame.kind, Kind::Group | Kind::Call),
                    gen::RPRACKET => matches!(frame.kind, Kind::List | Kind::Index),
                    _ => frame.kind == Kind::Map,
                };
                if !matches {
                    return Err(error(source, pos, "Syntax error: mismatched closing bracket; balance the brackets before parsing".into()));
                }
                let child = frames.pop().unwrap();
                // Preserve the entire parent chain AND the maximum child path.
                frames.last_mut().unwrap().segment += child.height();
                operand = false;
            }
            gen::LOGICAL_AND | gen::LOGICAL_OR => {
                frame.reset_segment();
                if ty == gen::LOGICAL_AND {
                    frame.ands += 1;
                } else {
                    frame.ors += 1;
                }
                operand = true;
            }
            gen::COMMA => {
                if !matches!(frame.kind, Kind::Call | Kind::List | Kind::Map) {
                    return Err(error(source, pos, "Syntax error: comma outside an argument or initializer list; correct the separator".into()));
                }
                frame.finish_expression();
                operand = true;
            }
            gen::QUESTIONMARK if previous == gen::DOT || operand => {
                // Optional select/index/initializer syntax has no ternary else.
                // It must not reset an existing segment, even if malformed.
                frame.segment += 1;
            }
            gen::QUESTIONMARK => {
                frame.peak = frame.peak.max(frame.segment + frame.persistent) + 1;
                frame.segment = 0;
                frame.persistent += 1;
                frame.pending_questions += 1;
                operand = true;
            }
            gen::COLON => {
                if frame.pending_questions > 0 {
                    frame.pending_questions -= 1;
                    frame.reset_segment(); // persistent else recursion remains
                } else if frame.kind == Kind::Map {
                    frame.finish_expression();
                } else {
                    return Err(error(source, pos, "Syntax error: colon without a conditional or map entry; correct the separator".into()));
                }
                operand = true;
            }
            gen::DOT => {
                frame.segment += 1;
                operand = true;
            }
            gen::EXCLAM
            | gen::MINUS
            | gen::PLUS
            | gen::STAR
            | gen::SLASH
            | gen::PERCENT
            | gen::EQUALS
            | gen::NOT_EQUALS
            | gen::IN
            | gen::LESS
            | gen::LESS_EQUALS
            | gen::GREATER
            | gen::GREATER_EQUALS => {
                frame.segment += 1;
                operand = true;
            }
            _ => {
                operand = false;
            }
        }
        let frame = frames.last_mut().unwrap();
        frame.peak = frame.peak.max(frame.segment + frame.persistent);
        measures.max_frame_chain = measures
            .max_frame_chain
            .max(1 + frame.base + frame.height());
        if measures.max_frame_chain > chain_limit {
            return Err(limit_error(
                source,
                pos,
                span,
                "frame chain",
                measures.max_frame_chain,
                chain_limit,
            ));
        }
        macro_allowance = if ty == gen::IDENTIFIER && previous == gen::DOT {
            match token.get_text() {
                "filter" => 4,
                "map" => 3,
                "all" | "exists" | "exists_one" | "existsOne" => 2,
                _ => 0,
            }
        } else {
            0
        };
        previous = ty;
    }
    if frames.len() != 1 {
        let line = source.bytes().filter(|&c| c == b'\n').count() as isize + 1;
        let col = source.rsplit('\n').next().unwrap_or("").chars().count() as isize + 1;
        return Err(error(
            source,
            (line, col),
            "Syntax error: unclosed bracket; balance the brackets before parsing".into(),
        ));
    }
    Ok(measures)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::Parser;
    use std::process::Command;

    fn nested(left: &str, atom: &str, right: &str, n: usize) -> String {
        format!("{}{}{}", left.repeat(n), atom, right.repeat(n))
    }

    fn shapes(n: usize) -> Vec<(&'static str, String)> {
        vec![
            ("select", format!("a{}", ".f".repeat(n))),
            ("add", format!("1{}", "+1".repeat(n))),
            ("relation", format!("1{}", "==1".repeat(n))),
            ("unary", format!("{}true", "!".repeat(n))),
            ("negate", format!("{}1", "-".repeat(n))),
            ("group", nested("(", "1", ")", n)),
            ("list", nested("[", "1", "]", n)),
            ("map", nested("{'k':", "1", "}", n)),
            ("call", nested("f(", "1", ")", n)),
            ("index_child", nested("a[", "0", "]", n)),
            ("index_chain", format!("a{}", "[0]".repeat(n))),
            ("receiver_chain", format!("a{}", ".f()".repeat(n))),
            ("ternary_else", format!("{}1", "true?1:".repeat(n))),
            ("all", nested("[1].all(x,", "true", ")", n)),
            ("exists", nested("[1].exists(x,", "true", ")", n)),
            ("exists_one", nested("[1].exists_one(x,", "true", ")", n)),
            ("map_macro", nested("[1].map(x,", "x", ")", n)),
            ("filter", nested("[1].filter(x,", "true", ")", n)),
            ("filtered_map", nested("[1].map(x,true,", "x", ")", n)),
            ("mixed", nested("f(a[true?1:", "1", "]).f", n)),
            ("alternating", nested("!f([{'k':a[true?1:", "1", "]}])", n)),
            (
                "mixed_arithmetic",
                nested("-f((a.f+(true?1:", "1", ")))", n),
            ),
            (
                "mixed_macro",
                nested("([1].map(x,!f(a[true?1:", "x", "]+1)).f)", n),
            ),
            ("logic_child", nested("f(true&&true||", "true", ")", n)),
            // Forces logical balancing and a deep branch in the same frame.
            (
                "logic_and_chain",
                format!("true||{}a{}", "true&&".repeat(n), ".f".repeat(n)),
            ),
            (
                "closed_group_chain",
                format!("(a{}).f{}", ".f".repeat(n), ".f".repeat(n)),
            ),
        ]
    }

    fn boundary_shapes(limit: usize) -> Vec<(&'static str, usize, String)> {
        let mut accepted = Vec::new();
        for i in 0..shapes(0).len() {
            let mut last = None;
            for n in 0..=limit + 1 {
                let (name, source) = shapes(n).swap_remove(i);
                match measure(&source, MAX_SOURCE_BYTES, MAX_PARSE_TOKENS, limit) {
                    Ok(m) => last = Some((name, n, source, m)),
                    Err(err) => {
                        assert!(err.to_string().contains("L0 frame chain"), "{name}: {err}");
                        if limit == MAX_PARSE_DEPTH {
                            assert_eq!(
                                Parser::new().parse(&source).unwrap_err().to_string(),
                                err.to_string(),
                                "{name}: just-over source entered recursive parsing"
                            );
                        }
                        let (name, n, source, m) = last.take().unwrap();
                        eprintln!(
                            "boundary {name}: n={n} bytes={} tokens={} chain={}",
                            m.bytes, m.real_tokens, m.max_frame_chain
                        );
                        accepted.push((name, n, source));
                        break;
                    }
                }
            }
        }
        accepted
    }

    #[test]
    fn lexer_measures_and_located_limits() {
        let plain = check("a.f[0] + 1").unwrap();
        let hidden = check("// .[(!+ ignored\na . f [ 0 ] // )ignored\n + 1").unwrap();
        assert_eq!(plain.real_tokens, hidden.real_tokens);
        assert_eq!(plain.max_frame_chain, hidden.max_frame_chain);
        let unicode = check("'💖é' + r'.[&&!?]' + b'abc'").unwrap();
        assert_eq!(unicode.real_tokens, 5);
        assert_eq!(unicode.bytes, "'💖é' + r'.[&&!?]' + b'abc'".len());
        for source in [
            "r'''.[!?&&]'''",
            "b'\\xFF'",
            "'\\u1234'",
            "0x1234u",
            "`a.b`",
        ] {
            assert_eq!(check(source).unwrap().real_tokens, 1, "{source}");
        }
        let source = format!("'{}'", "é".repeat((MAX_SOURCE_BYTES - 2) / 2));
        assert_eq!(check(&source).unwrap().bytes, MAX_SOURCE_BYTES);
        let err = check(&(source + " ")).unwrap_err();
        assert!(err
            .to_string()
            .contains("source bytes 16385 exceeds limit 16384"));
        assert!(err.errors[0].pos.0 > 0 && err.errors[0].pos.1 > 0);
        assert!(err.errors[0].source_info.is_some());
        let source = format!("![{}]", vec!["0"; 1023].join(",")); // 2048 tokens
        assert_eq!(check(&source).unwrap().real_tokens, MAX_PARSE_TOKENS);
        let source = format!("[{}0]", "0,".repeat(1023)); // 2049
        assert!(check(&source)
            .unwrap_err()
            .to_string()
            .contains("tokens 2049 exceeds limit 2048"));
        assert!(Parser::new().max_parse_tokens(2).parse("1 + 2").is_err());
        assert!(Parser::new().max_source_bytes(2).parse("123").is_err());
    }

    #[test]
    fn frames_persist_across_segments_and_closes() {
        assert_eq!(check("a.f").unwrap().max_frame_chain, 2);
        assert_eq!(check("(a.f).g").unwrap().max_frame_chain, 5);
        assert_eq!(check("a[0][0]").unwrap().max_frame_chain, 5);
        assert_eq!(check("[[0]]").unwrap().max_frame_chain, 5);
        assert_eq!(check("f(g(0))").unwrap().max_frame_chain, 5);
        assert_eq!(check("true?0:true?0:1").unwrap().max_frame_chain, 3);
        assert_eq!(check("a.f?0:1").unwrap().max_frame_chain, 3);
        assert_eq!(check("[a.f,b.g]").unwrap().max_frame_chain, 4);
        assert!(
            check("[1].filter(x,true)").unwrap().max_frame_chain
                > check("[1].f(x,true)").unwrap().max_frame_chain
        );
        for (_, _, source) in boundary_shapes(MAX_PARSE_DEPTH) {
            assert!(check(&source).is_ok());
        }
        for source in [
            format!("a{}", ".f".repeat(MAX_PARSE_DEPTH)),
            format!("{}1", "true?1:".repeat(MAX_PARSE_DEPTH)),
            format!("(a{}){}", ".f".repeat(50), ".f".repeat(50)),
            nested("a[", "0", "]", MAX_PARSE_DEPTH),
        ] {
            let err = check(&source).unwrap_err();
            assert!(err.to_string().contains("L0 frame chain"));
            // Parser returns that exact guard diagnostic before ANTLR starts.
            assert_eq!(
                Parser::new().parse(&source).unwrap_err().to_string(),
                err.to_string()
            );
        }
    }

    #[test]
    fn wide_rules_and_source_info() {
        for count in [20, 30, 40] {
            let source = (0..count)
                .map(|i| format!("input{i}.a > other{i}.b"))
                .collect::<Vec<_>>()
                .join(" && ");
            let m = check(&source).unwrap();
            assert!(m.max_frame_chain < 32);
            let (ast, info) = Parser::new().parse_with_source_info(&source).unwrap();
            assert_eq!(info.source, source);
            assert!(info.offset_for(ast.id).is_some());
            drop((ast, info));
        }
        for source in [
            nested("(", "1", ")", 32),
            nested("f(", "1", ")", 31),
            format!("{}1", "true?1:".repeat(31)),
        ] {
            probe("L1 listener", &source, 8 * 1024 * 1024, false);
        }
    }

    #[test]
    fn malformed_sources_cannot_bypass_guard() {
        for source in [
            "a @ .b",
            "'unterminated",
            "💖",
            "a , b",
            "a : b",
            "([)]",
            "f([1)",
            "f(1",
            "a[0]]",
        ] {
            assert!(check(source).is_err(), "{source}");
        }
        for source in [
            format!("a{}", ".?f".repeat(MAX_PARSE_DEPTH)),
            format!("{}true", "!?".repeat(MAX_PARSE_DEPTH)),
            format!("[{}", "f(".repeat(MAX_PARSE_DEPTH)),
        ] {
            assert!(check(&source).is_err(), "{source}");
        }
        // Structurally balanced but grammatically malformed: these enter bounded
        // ANTLR recovery. Isolated stack probes also exercise their deep versions.
        for source in ["f(1,)", "1++2", "[?]", "a ? : b", "a && && b"] {
            assert!(Parser::new().parse(source).is_err(), "{source}");
        }
    }

    /// Both the parent and child are ordinary tests. Child environment belongs to
    /// Command only; parallel tests never observe a mutated process environment.
    #[test]
    fn native_stack_probe_child() {
        let Ok(source) = std::env::var("CEL_L0_PROBE_SOURCE") else {
            return;
        };
        let stack: usize = std::env::var("CEL_L0_PROBE_STACK")
            .unwrap()
            .parse()
            .unwrap();
        let expect_error = std::env::var_os("CEL_L0_PROBE_ERROR").is_some();
        std::thread::Builder::new()
            .stack_size(stack)
            .spawn(move || {
                let result = Parser::new().parse_with_source_info(&source);
                if expect_error {
                    assert!(
                        check(&source).is_ok(),
                        "malformed probe did not reach ANTLR: {source}"
                    );
                    let err = result.unwrap_err();
                    assert!(
                        !err.to_string().contains("L0"),
                        "guard refused instead of recovery: {source}"
                    );
                } else {
                    let (ast, info) = result.unwrap_or_else(|err| {
                        panic!("parse/listener failure: {err}; source={source}")
                    });
                    assert_eq!(info.source, source);
                    assert!(
                        ast_depth(&ast) <= check(&source).unwrap().max_frame_chain,
                        "L0 underestimated expanded AST: {source}"
                    );
                    drop((ast, info)); // visitor and parse-tree drop occurred in parse; AST drops here
                }
            })
            .unwrap()
            .join()
            .expect("probe thread panicked (distinct from process stack abort)");
    }

    fn ast_depth(root: &crate::common::ast::IdedExpr) -> usize {
        use crate::common::ast::{EntryExpr, Expr};
        let mut pending = vec![(root, 1)];
        let mut max = 0;
        while let Some((expr, depth)) = pending.pop() {
            max = max.max(depth);
            let mut push = |child| pending.push((child, depth + 1));
            match &expr.expr {
                Expr::Call(call) => {
                    if let Some(target) = &call.target {
                        push(target.as_ref());
                    }
                    for arg in &call.args {
                        push(arg);
                    }
                }
                Expr::Select(select) => push(select.operand.as_ref()),
                Expr::List(list) => {
                    for child in &list.elements {
                        push(child);
                    }
                }
                Expr::Map(map) => {
                    for entry in &map.entries {
                        if let EntryExpr::MapEntry(e) = &entry.expr {
                            push(&e.key);
                            push(&e.value);
                        }
                    }
                }
                Expr::Struct(st) => {
                    for entry in &st.entries {
                        if let EntryExpr::StructField(e) = &entry.expr {
                            push(&e.value);
                        }
                    }
                }
                Expr::Comprehension(c) => {
                    push(&c.iter_range);
                    push(&c.accu_init);
                    push(&c.loop_cond);
                    push(&c.loop_step);
                    push(&c.result);
                }
                _ => {}
            }
        }
        max
    }

    #[test]
    fn generated_alternatives_and_recovery() {
        // Primary 1..7, unary 1..3, member alternatives, calc alternatives and
        // relation. Arbitrary message types parse here; subset policy is separate.
        for source in [
            "a",
            ".a",
            "f()",
            ".f(1,2)",
            "(1)",
            "[1,2,]",
            "{'a':1,'b':2,}",
            "pkg.Msg{a:1,b:[2]}",
            "1",
            "1u",
            "1.2",
            "'é'",
            "b'\\xFF'",
            "true",
            "false",
            "null",
            "!a",
            "--a",
            "-1",
            "a.f",
            "a.`f.g`",
            "a.f(1,2)",
            "a[0]",
            "1*2/3%4+5-6",
            "a < b <= c > d >= e == f != g in h",
            "a?b:c?d:e",
            "[?a,?b]",
            "a.?f[?0]",
            "{?'a':1}",
            "Msg{?a:1}",
        ] {
            let (ast, info) = Parser::new()
                .enable_optional_syntax(true)
                .enable_ident_escape_syntax(true)
                .parse_with_source_info(source)
                .unwrap_or_else(|err| panic!("{source}: {err}"));
            assert!(
                ast_depth(&ast) <= check(source).unwrap().max_frame_chain,
                "{source}"
            );
            assert!(info.offset_for(ast.id).is_some());
        }
        // Each bracket context reaches generated recovery with balanced tokens.
        for source in [
            "f(1,)",
            "(1,)",
            "[1,,2]",
            "{'a':}",
            "pkg.Msg{a:}",
            "a.f(,)",
            "a[]",
            "!+a",
            "1*+2",
            "1==",
            "a?:b",
        ] {
            assert!(Parser::new().parse(source).is_err(), "{source}");
        }
    }

    fn probe(name: &str, source: &str, stack: usize, expect_error: bool) {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "parser::l0::tests::native_stack_probe_child",
                "--nocapture",
            ])
            .env("CEL_L0_PROBE_SOURCE", source)
            .env("CEL_L0_PROBE_STACK", stack.to_string())
            .env_remove("CEL_L0_PROBE_ERROR");
        if expect_error {
            command.env("CEL_L0_PROBE_ERROR", "1");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "isolated {name} failed on {stack} bytes: status={}\nstdout={}\nstderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn native_stack_headroom() {
        // Override only the thread-stack search, never the production guard caps.
        let stacks = match std::env::var("CEL_L0_PROBE_STACKS") {
            Ok(s) => s
                .split(',')
                .map(|v| v.parse().unwrap())
                .collect::<Vec<usize>>(),
            Err(_) => vec![4 * 1024 * 1024, 8 * 1024 * 1024],
        };
        let mut sources = boundary_shapes(MAX_PARSE_DEPTH);
        sources.push((
            "token_ceiling",
            0,
            format!("![{}]", vec!["0"; 1023].join(",")),
        ));
        sources.push((
            "source_ceiling",
            0,
            format!("'{}'", "x".repeat(MAX_SOURCE_BYTES - 2)),
        ));
        sources.push(("wide_logic", 0, vec!["a.f==b.g"; 256].join("&&"))); // 2047 tokens
        for stack in stacks {
            for (name, n, source) in &sources {
                eprintln!("probe {name} n={n} stack={stack}");
                probe(name, source, stack, false);
            }
            for (name, source) in [
                (
                    "malformed_add",
                    format!("1{}", "+".repeat(MAX_PARSE_DEPTH - 1)),
                ),
                (
                    "malformed_ternary",
                    format!("{}1", "true?:".repeat(MAX_PARSE_DEPTH - 1)),
                ),
                (
                    "malformed_group",
                    nested("(", "1++", ")", (MAX_PARSE_DEPTH - 3) / 2),
                ),
            ] {
                eprintln!("probe {name} stack={stack} (guard-admitted recovery)");
                probe(name, &source, stack, true);
            }
        }
    }
}
