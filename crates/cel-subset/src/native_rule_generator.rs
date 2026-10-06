//! Deterministic private DATA grammar, not an admission or execution harness.
//!
//! The explicit typed tree has no parser IDs/positions. Canonical fingerprints
//! preserve literal values; structural fingerprints erase them and alpha-rename
//! bound variables to de Bruijn distances. Exact strings decide uniqueness; the
//! exported FNV-1a hashes are convenient labels, not collision-proof evidence.
//! Main must count actual admissions/rejections through its public checked API.
use super::native_fixture_sets::{Clause, Expected, Fixture, GuardDescriptor, Scenario, Source};
use crate::{InputDecl, InputKind, ScalarType, Value};
use indexmap::IndexMap;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const GENERATOR_VERSION: &str = "native-typed-grammar-v2";
pub(crate) const DEFAULT_SEED: u64 = 0x6791_0303_621b_61e5;
// Grammar bounds, not configurable production policy or measured admission.
const DEPTH_BOUND: usize = 30;
const NODE_BOUND: usize = 420;
const SOURCE_BOUND: usize = 7_000;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Type {
    Int,
    UInt,
    Double,
    Bool,
    Text,
    Bytes,
    Duration,
    Timestamp,
    Row,
    Map,
    KeyMap(Box<Type>),
    List(Box<Type>),
    Any,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Literal {
    Int(i64),
    UInt(u64),
    Double(String),
    Bool(bool),
    Text(String),
    Bytes(String),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Variable {
    Global(String),
    Bound { name: String, distance: usize },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unary {
    Not,
    Negate,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Binary {
    Add,
    Subtract,
    Multiply,
    Divide,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    And,
    Or,
    In,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Macro {
    Map,
    Filter,
    All,
    Exists,
    ExistsOne,
    MapThree,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Ast {
    pub ty: Type,
    pub node: Node,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Node {
    Literal(Literal),
    Variable(Variable),
    Select {
        target: Box<Ast>,
        field: String,
    },
    Index {
        target: Box<Ast>,
        index: Box<Ast>,
    },
    Unary {
        op: Unary,
        value: Box<Ast>,
    },
    Binary {
        op: Binary,
        left: Box<Ast>,
        right: Box<Ast>,
    },
    Conditional {
        condition: Box<Ast>,
        yes: Box<Ast>,
        no: Box<Ast>,
    },
    Call {
        name: String,
        receiver: Option<Box<Ast>>,
        args: Vec<Ast>,
    },
    List(Vec<Ast>),
    Map(Vec<(Ast, Ast)>),
    Macro {
        kind: Macro,
        range: Box<Ast>,
        variable: String,
        body: Box<Ast>,
        predicate: Option<Box<Ast>>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TypedClause {
    pub when: Ast,
    pub result: Ast,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TypedSource {
    Expression(Ast),
    Clauses(Vec<TypedClause>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TypedGuard {
    pub pending_input_name: String,
    pub expression: Ast,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RuleTree {
    pub source: TypedSource,
    pub guards: Vec<TypedGuard>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Metadata {
    pub family: &'static str,
    pub output_types: Vec<Type>,
    pub nodes: usize,
    /// Conservative grammar bound, independently compared with actual parse AST in tests.
    pub expanded_depth_bound: usize,
    pub comprehension_body_depth: usize,
    pub features: BTreeMap<String, usize>,
    pub intentional_semantic_error: bool,
}
#[derive(Clone, Debug)]
pub(crate) struct GeneratedRule {
    pub fixture: Fixture,
    pub tree: RuleTree,
    pub metadata: Metadata,
    pub canonical_fingerprint: String,
    pub structural_fingerprint: String,
    pub canonical_hash: u64,
    pub structural_hash: u64,
    pub attempt: usize,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counts {
    pub requested_successes: usize,
    pub generated_candidates: usize,
    pub successful_candidates: usize,
    pub semantic_error_candidates: usize,
    pub attempts: usize,
    pub retries: usize,
    pub canonical_duplicates: usize,
    pub structural_duplicates: usize,
    pub grammar_limit_rejections: usize,
    pub exhausted_attempt_budget: bool,
    pub attempted_by_family: BTreeMap<String, usize>,
    pub generated_by_family: BTreeMap<String, usize>,
    pub generated_by_output_type: BTreeMap<String, usize>,
    pub features: BTreeMap<String, usize>,
}
#[derive(Clone, Debug)]
pub(crate) struct GeneratedSet {
    pub seed: u64,
    pub version: &'static str,
    pub counts: Counts,
    /// Success and error candidates are explicitly labeled; no refusals in this set.
    pub rules: Vec<GeneratedRule>,
}

// SplitMix64: the entire PRNG state and operation order is versioned here.
struct Random(u64);
impl Random {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn pick(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}
#[derive(Clone, Default)]
struct Scope {
    locals: Vec<(String, Type)>,
    body_depth: usize,
    many_allowed: bool,
    one_allowed: bool,
}
impl Scope {
    fn root() -> Self {
        Self {
            many_allowed: true,
            one_allowed: true,
            ..Self::default()
        }
    }
    fn bind(&self, name: &str, ty: Type, many: bool) -> Self {
        let mut result = self.clone();
        result.locals.push((name.into(), ty));
        result.body_depth += 1;
        result.many_allowed &= !many;
        result
    }
    fn local(&self, ty: &Type) -> Option<Ast> {
        let mut visible = BTreeSet::new();
        for (distance, (name, kind)) in self.locals.iter().rev().enumerate() {
            if visible.insert(name) && kind == ty {
                return Some(Ast {
                    ty: ty.clone(),
                    node: Node::Variable(Variable::Bound {
                        name: name.clone(),
                        distance,
                    }),
                });
            }
        }
        None
    }
}
fn list_type(ty: Type) -> Type {
    Type::List(Box::new(ty))
}
fn ast(ty: Type, node: Node) -> Ast {
    Ast { ty, node }
}
fn global(name: &str, ty: Type) -> Ast {
    ast(ty, Node::Variable(Variable::Global(name.into())))
}
fn int(value: i64) -> Ast {
    ast(Type::Int, Node::Literal(Literal::Int(value)))
}
fn text(value: &str) -> Ast {
    ast(Type::Text, Node::Literal(Literal::Text(value.into())))
}
fn boolean(value: bool) -> Ast {
    ast(Type::Bool, Node::Literal(Literal::Bool(value)))
}
fn literal_number(rng: &mut Random, ty: &Type) -> Ast {
    let n = 1 + rng.pick(8);
    match ty {
        Type::Int => int(n as i64),
        Type::UInt => ast(Type::UInt, Node::Literal(Literal::UInt(n as u64))),
        Type::Double => ast(
            Type::Double,
            Node::Literal(Literal::Double(format!("{n}.5"))),
        ),
        _ => unreachable!("numeric grammar"),
    }
}
fn binary(ty: Type, op: Binary, left: Ast, right: Ast) -> Ast {
    ast(
        ty,
        Node::Binary {
            op,
            left: Box::new(left),
            right: Box::new(right),
        },
    )
}
fn unary(ty: Type, op: Unary, value: Ast) -> Ast {
    ast(
        ty,
        Node::Unary {
            op,
            value: Box::new(value),
        },
    )
}
fn call(ty: Type, name: &str, receiver: Option<Ast>, args: Vec<Ast>) -> Ast {
    ast(
        ty,
        Node::Call {
            name: name.into(),
            receiver: receiver.map(Box::new),
            args,
        },
    )
}
fn select(target: Ast, field: &str, ty: Type) -> Ast {
    ast(
        ty,
        Node::Select {
            target: Box::new(target),
            field: field.into(),
        },
    )
}
fn list(ty: Type, entries: Vec<Ast>) -> Ast {
    ast(list_type(ty), Node::List(entries))
}
fn key_map(kind: Type, entries: Vec<(Ast, Ast)>) -> Ast {
    ast(Type::KeyMap(Box::new(kind)), Node::Map(entries))
}
fn map(entries: Vec<(Ast, Ast)>) -> Ast {
    ast(Type::Map, Node::Map(entries))
}
fn conditional(ty: Type, condition: Ast, yes: Ast, no: Ast) -> Ast {
    ast(
        ty,
        Node::Conditional {
            condition: Box::new(condition),
            yes: Box::new(yes),
            no: Box::new(no),
        },
    )
}
fn macro_expr(kind: Macro, range: Ast, variable: &str, body: Ast, predicate: Option<Ast>) -> Ast {
    let ty = match kind {
        Macro::All | Macro::Exists | Macro::ExistsOne => Type::Bool,
        Macro::Filter => range.ty.clone(),
        Macro::Map | Macro::MapThree => list_type(body.ty.clone()),
    };
    ast(
        ty,
        Node::Macro {
            kind,
            range: Box::new(range),
            variable: variable.into(),
            body: Box::new(body),
            predicate: predicate.map(Box::new),
        },
    )
}
fn row_ref(scope: &Scope) -> Option<Ast> {
    scope
        .local(&Type::Row)
        .or_else(|| scope.one_allowed.then(|| global("one", Type::Row)))
}
fn size(rng: &mut Random, target: Ast) -> Ast {
    if rng.pick(2) == 0 {
        call(Type::Int, "size", None, vec![target])
    } else {
        call(Type::Int, "size", Some(target), vec![])
    }
}
fn numeric_type(rng: &mut Random) -> Type {
    [Type::Int, Type::UInt, Type::Double][rng.pick(3)].clone()
}

// Typed recursive productions. Multiplication/division use a small literal RHS;
// subtraction is omitted for UInt. Successful numeric trees cannot overflow with
// the fixed scalar domain and depth used here. No string -> number casts from
// arbitrary inputs occur in a success production.
fn number(rng: &mut Random, ty: Type, depth: usize, scope: &Scope) -> Ast {
    if depth == 0 {
        if ty == Type::Int {
            match rng.pick(5) {
                0 => return global("n", Type::Int),
                1 => return global("m", Type::Int),
                2 => {
                    if let Some(local) = scope.local(&Type::Int) {
                        return local;
                    }
                }
                3 => {
                    if let Some(row) = row_ref(scope) {
                        return select(row, "n", Type::Int);
                    }
                }
                _ => {}
            }
        }
        return literal_number(rng, &ty);
    }
    match rng.pick(8) {
        0 => {
            let value = number(rng, ty.clone(), 0, scope);
            if ty != Type::UInt && rng.pick(2) == 0 {
                unary(ty, Unary::Negate, value)
            } else {
                value
            }
        }
        1 => {
            let a = number(rng, ty.clone(), depth - 1, scope);
            let b = number(rng, ty.clone(), depth - 1, scope);
            binary(ty, Binary::Add, a, b)
        }
        2 => {
            let a = number(rng, ty.clone(), depth - 1, scope);
            let b = literal_number(rng, &ty);
            binary(ty, Binary::Multiply, a, b)
        }
        3 if ty != Type::UInt => {
            let a = number(rng, ty.clone(), depth - 1, scope);
            let b = number(rng, ty.clone(), depth - 1, scope);
            binary(ty, Binary::Subtract, a, b)
        }
        4 => {
            let a = number(rng, ty.clone(), depth - 1, scope);
            let b = literal_number(rng, &ty);
            binary(ty, Binary::Divide, a, b)
        }
        5 => {
            let condition = predicate(rng, depth - 1, scope);
            let yes = number(rng, ty.clone(), depth - 1, scope);
            let no = number(rng, ty.clone(), depth - 1, scope);
            conditional(ty, condition, yes, no)
        }
        6 => {
            let entries = (0..2 + rng.pick(2))
                .map(|_| number(rng, ty.clone(), depth - 1, scope))
                .collect();
            let target = list(ty.clone(), entries);
            let name = if rng.pick(2) == 0 { "min" } else { "max" };
            if rng.pick(2) == 0 {
                call(ty, name, None, vec![target])
            } else {
                call(ty, name, Some(target), vec![])
            }
        }
        _ => match ty {
            Type::Int => {
                let t = words(rng, depth - 1, scope);
                size(rng, t)
            }
            Type::UInt | Type::Double => {
                let name = if ty == Type::UInt { "uint" } else { "double" };
                let x = literal_number(rng, &Type::Int);
                call(ty, name, None, vec![x])
            }
            _ => unreachable!(),
        },
    }
}
fn words(rng: &mut Random, depth: usize, scope: &Scope) -> Ast {
    if depth == 0 {
        return match rng.pick(4) {
            0 => global("text", Type::Text),
            1 => row_ref(scope)
                .map(|r| select(r, "body", Type::Text))
                .unwrap_or_else(|| text("rowless")),
            2 => text(["alpha", "beta", "x", "escaped\ntext"][rng.pick(4)]),
            _ => text(""),
        };
    }
    match rng.pick(5) {
        0 => words(rng, 0, scope),
        1 => {
            let a = words(rng, depth - 1, scope);
            let b = words(rng, depth - 1, scope);
            binary(Type::Text, Binary::Add, a, b)
        }
        2 => {
            let ty = numeric_type(rng);
            let x = number(rng, ty, depth - 1, scope);
            call(Type::Text, "string", None, vec![x])
        }
        3 => {
            let c = predicate(rng, depth - 1, scope);
            let a = words(rng, depth - 1, scope);
            let b = words(rng, depth - 1, scope);
            conditional(Type::Text, c, a, b)
        }
        _ => {
            let x = words(rng, depth - 1, scope);
            let bytes = call(Type::Bytes, "bytes", None, vec![x]);
            call(Type::Text, "string", None, vec![bytes])
        }
    }
}
fn predicate(rng: &mut Random, depth: usize, scope: &Scope) -> Ast {
    if depth == 0 {
        return match rng.pick(4) {
            0 => global("flag", Type::Bool),
            1 => row_ref(scope)
                .map(|r| select(r, "ok", Type::Bool))
                .unwrap_or_else(|| boolean(true)),
            _ => boolean(rng.pick(2) == 0),
        };
    }
    match rng.pick(9) {
        0 => unary(Type::Bool, Unary::Not, predicate(rng, depth - 1, scope)),
        1 | 2 => {
            let op = if rng.pick(2) == 0 {
                Binary::And
            } else {
                Binary::Or
            };
            let a = predicate(rng, depth - 1, scope);
            let b = predicate(rng, depth - 1, scope);
            binary(Type::Bool, op, a, b)
        }
        3 => {
            let ty = numeric_type(rng);
            let a = number(rng, ty.clone(), depth - 1, scope);
            let b = number(rng, ty, depth - 1, scope);
            let op = [
                Binary::Equal,
                Binary::NotEqual,
                Binary::Less,
                Binary::LessEqual,
                Binary::Greater,
                Binary::GreaterEqual,
            ][rng.pick(6)];
            binary(Type::Bool, op, a, b)
        }
        4 => {
            let a = words(rng, depth - 1, scope);
            let b = words(rng, depth - 1, scope);
            let name = ["contains", "startsWith", "endsWith"][rng.pick(3)];
            call(Type::Bool, name, Some(a), vec![b])
        }
        5 if scope.body_depth < 2 => {
            let many = scope.many_allowed && rng.pick(2) == 0;
            let (range, elem) = if many {
                (global("xs", list_type(Type::Row)), Type::Row)
            } else {
                (list(Type::Int, vec![int(0), int(1)]), Type::Int)
            };
            let inner = scope.bind("r", elem, many);
            let body = predicate(rng, depth - 1, &inner);
            let kind = [Macro::All, Macro::Exists, Macro::ExistsOne][rng.pick(3)];
            macro_expr(kind, range, "r", body, None)
        }
        6 => {
            let a = number(rng, Type::Int, depth - 1, scope);
            let values = (0..3)
                .map(|_| number(rng, Type::Int, depth - 1, scope))
                .collect();
            let target = list(Type::Int, values);
            if rng.pick(2) == 0 {
                binary(Type::Bool, Binary::In, a, target)
            } else {
                call(Type::Bool, "contains", Some(target), vec![a])
            }
        }
        7 => {
            let a = words(rng, depth - 1, scope);
            let pattern = text(["a.*", "[ab]+", "x?"][rng.pick(3)]);
            if rng.pick(2) == 0 {
                call(Type::Bool, "matches", Some(a), vec![pattern])
            } else {
                call(Type::Bool, "matches", None, vec![a, pattern])
            }
        }
        _ => predicate(rng, 0, scope),
    }
}
fn scalar_tree(rng: &mut Random, depth: usize, scope: &Scope) -> Ast {
    match rng.pick(5) {
        0 => predicate(rng, depth, scope),
        1 => words(rng, depth, scope),
        _ => {
            let ty = numeric_type(rng);
            number(rng, ty, depth, scope)
        }
    }
}
fn temporal(rng: &mut Random, depth: usize, timestamp: bool, scope: &Scope) -> Ast {
    let ty = if timestamp {
        Type::Timestamp
    } else {
        Type::Duration
    };
    if depth == 0 {
        let value = if timestamp {
            [
                "2000-01-01T00:00:00Z",
                "2026-10-03T00:00:00Z",
                "0001-01-01T00:00:00Z",
            ][rng.pick(3)]
            .into()
        } else {
            format!("{}s", 1 + rng.pick(7))
        };
        return call(
            ty,
            if timestamp { "timestamp" } else { "duration" },
            None,
            vec![text(&value)],
        );
    }
    match rng.pick(3) {
        0 => {
            let c = predicate(rng, depth - 1, scope);
            let a = temporal(rng, depth - 1, timestamp, scope);
            let b = temporal(rng, depth - 1, timestamp, scope);
            conditional(ty, c, a, b)
        }
        1 => {
            let x = temporal(rng, depth - 1, timestamp, scope);
            call(
                ty,
                if timestamp { "timestamp" } else { "duration" },
                None,
                vec![x],
            )
        }
        _ => {
            let a = temporal(rng, depth - 1, timestamp, scope);
            let b = call(Type::Duration, "duration", None, vec![text("1s")]);
            binary(ty, Binary::Add, a, b)
        }
    }
}

const FAMILIES: &[&str] = &[
    "numeric",
    "boolean",
    "text",
    "aggregate-output",
    "byte-output",
    "row-copy-projection",
    "macro-map",
    "macro-filter",
    "macro-all",
    "macro-exists",
    "macro-exists-one",
    "macro-three-map",
    "sequential-loops",
    "shadowing-inner",
    "row-local-inner",
    "linear-many-size",
    "temporal-success",
    "numeric-extrema",
    "numeric-map-keys",
    "bool-map-keys",
    "mixed-map-keys",
    "whole-rule",
    "ordered-guards",
];
fn success_tree(rng: &mut Random, family: &str) -> RuleTree {
    let scope = Scope::root();
    let depth = 3 + rng.pick(2);
    let expression = match family {
        "numeric" => {
            let ty = numeric_type(rng);
            number(rng, ty, depth, &scope)
        }
        "boolean" => predicate(rng, depth, &scope),
        "text" => words(rng, depth, &scope),
        "aggregate-output" => {
            let payload = scalar_tree(rng, depth, &scope);
            let copied = if rng.pick(2) == 0 {
                global("one", Type::Row)
            } else {
                global("xs", list_type(Type::Row))
            };
            let reason = words(rng, depth - 1, &scope);
            map(vec![
                (text("value"), payload),
                (text("copy"), copied),
                (text("reason"), reason),
            ])
        }
        "byte-output" => {
            let body = words(rng, depth, &scope);
            let bytes = call(Type::Bytes, "bytes", None, vec![body]);
            if rng.pick(2) == 0 {
                bytes
            } else {
                binary(
                    Type::Bytes,
                    Binary::Add,
                    bytes,
                    ast(Type::Bytes, Node::Literal(Literal::Bytes("xy".into()))),
                )
            }
        }
        "row-copy-projection" => {
            let inner = scope.bind("r", Type::Row, true);
            let r = inner.local(&Type::Row).unwrap();
            let extra = scalar_tree(rng, depth - 1, &inner);
            let body = map(vec![
                (text("twice"), list(Type::Row, vec![r.clone(), r.clone()])),
                (text("id"), select(r, "id", Type::Text)),
                (text("computed"), extra),
            ]);
            macro_expr(
                Macro::Map,
                global("xs", list_type(Type::Row)),
                "r",
                body,
                None,
            )
        }
        "macro-map" | "macro-filter" | "macro-all" | "macro-exists" | "macro-exists-one"
        | "macro-three-map" => {
            let inner = scope.bind("r", Type::Row, true);
            let kind = match family {
                "macro-map" => Macro::Map,
                "macro-filter" => Macro::Filter,
                "macro-all" => Macro::All,
                "macro-exists" => Macro::Exists,
                "macro-exists-one" => Macro::ExistsOne,
                _ => Macro::MapThree,
            };
            let body = if matches!(kind, Macro::Map | Macro::MapThree) {
                scalar_tree(rng, depth, &inner)
            } else {
                predicate(rng, depth, &inner)
            };
            let filter = if kind == Macro::MapThree {
                Some(predicate(rng, depth - 1, &inner))
            } else {
                None
            };
            macro_expr(kind, global("xs", list_type(Type::Row)), "r", body, filter)
        }
        "sequential-loops" => {
            let row_scope = scope.bind("r", Type::Row, true);
            let first = macro_expr(
                Macro::Map,
                global("xs", list_type(Type::Row)),
                "r",
                number(rng, Type::Int, depth - 1, &row_scope),
                None,
            );
            let element_scope = scope.bind("v", Type::Int, true);
            let filtered = macro_expr(
                Macro::Filter,
                first,
                "v",
                predicate(rng, depth - 1, &element_scope),
                None,
            );
            macro_expr(
                Macro::Map,
                filtered,
                "v",
                number(rng, Type::Int, depth - 1, &element_scope),
                None,
            )
        }
        "shadowing-inner" | "row-local-inner" => {
            let outer = scope.bind("r", Type::Row, true);
            let name = if family == "shadowing-inner" {
                "r"
            } else {
                "k"
            };
            let inner = outer.bind(name, Type::Int, false);
            let body = number(rng, Type::Int, depth, &inner);
            let values = (0..1 + rng.pick(3))
                .map(|_| literal_number(rng, &Type::Int))
                .collect();
            let mapped = macro_expr(Macro::Map, list(Type::Int, values), name, body, None);
            macro_expr(
                Macro::Map,
                global("xs", list_type(Type::Row)),
                "r",
                mapped,
                None,
            )
        }
        "linear-many-size" => {
            let inner = scope.bind("r", Type::Row, true);
            let count = size(rng, global("ys", list_type(Type::Row)));
            let computed = number(rng, Type::Int, depth, &inner);
            let body = binary(Type::Int, Binary::Add, count, computed);
            macro_expr(
                Macro::Map,
                global("xs", list_type(Type::Row)),
                "r",
                body,
                None,
            )
        }
        "temporal-success" => {
            let timestamp = rng.pick(2) == 0;
            let value = temporal(rng, depth - 1, timestamp, &scope);
            if rng.pick(2) == 0 {
                value
            } else {
                call(Type::Text, "string", None, vec![value])
            }
        }
        "numeric-extrema" => {
            let ty = numeric_type(rng);
            let entries = (0..2 + rng.pick(3))
                .map(|_| number(rng, ty.clone(), depth, &scope))
                .collect();
            let values = list(ty.clone(), entries);
            let name = if rng.pick(2) == 0 { "min" } else { "max" };
            if rng.pick(2) == 0 {
                call(ty, name, None, vec![values])
            } else {
                call(ty, name, Some(values), vec![])
            }
        }
        "numeric-map-keys" | "bool-map-keys" | "mixed-map-keys" => {
            let a = scalar_tree(rng, depth, &scope);
            let b = scalar_tree(rng, depth - 1, &scope);
            let (key_kind, keys) = match family {
                "numeric-map-keys" => {
                    if rng.pick(2) == 0 {
                        (Type::Int, vec![int(1), int(2)])
                    } else {
                        (
                            Type::UInt,
                            vec![
                                ast(Type::UInt, Node::Literal(Literal::UInt(1))),
                                ast(Type::UInt, Node::Literal(Literal::UInt(2))),
                            ],
                        )
                    }
                }
                "bool-map-keys" => (Type::Bool, vec![boolean(false), boolean(true)]),
                _ => (Type::Any, vec![int(1), boolean(true), text("label")]),
            };
            let mut entries = vec![(keys[0].clone(), a), (keys[1].clone(), b)];
            if keys.len() == 3 {
                entries.push((keys[2].clone(), words(rng, depth - 1, &scope)));
            }
            let range = key_map(key_kind.clone(), entries);
            if rng.pick(2) == 0 {
                range
            } else {
                let inner = scope.bind("key", key_kind.clone(), false);
                let key = inner.local(&key_kind).unwrap();
                let body = match key_kind {
                    Type::Int | Type::UInt => {
                        let key = call(Type::Text, "string", None, vec![key]);
                        let suffix = words(rng, depth - 1, &inner);
                        binary(Type::Text, Binary::Add, key, suffix)
                    }
                    Type::Bool => {
                        let yes = words(rng, depth - 1, &inner);
                        let no = words(rng, depth - 1, &inner);
                        conditional(Type::Text, key, yes, no)
                    }
                    Type::Any => {
                        let key = call(Type::Any, "dyn", None, vec![key]);
                        let value = scalar_tree(rng, depth - 1, &inner);
                        map(vec![(text("key"), key), (text("value"), value)])
                    }
                    _ => unreachable!(),
                };
                macro_expr(Macro::Map, range, "key", body, None)
            }
        }
        "whole-rule" => {
            let count = 2 + rng.pick(3);
            let clauses = (0..count)
                .map(|i| TypedClause {
                    when: if i + 1 == count {
                        boolean(true)
                    } else {
                        predicate(rng, depth, &scope)
                    },
                    result: map(vec![
                        (text("decision"), words(rng, depth - 1, &scope)),
                        (
                            text("used"),
                            list(Type::Row, vec![global("one", Type::Row)]),
                        ),
                        (text("value"), scalar_tree(rng, depth - 1, &scope)),
                    ]),
                })
                .collect();
            return RuleTree {
                source: TypedSource::Clauses(clauses),
                guards: vec![],
            };
        }
        "ordered-guards" => {
            let mut scalar_scope = Scope::root();
            scalar_scope.one_allowed = false;
            scalar_scope.many_allowed = false;
            // Prefix before One one contains xs/ys and all scalar arguments. This
            // predicate intentionally uses only scalars and short literal ranges.
            let before_one = predicate(rng, depth, &scalar_scope);
            let after_one = predicate(rng, depth, &scope);
            let output = scalar_tree(rng, depth, &scope);
            return RuleTree {
                source: TypedSource::Expression(output),
                guards: vec![
                    TypedGuard {
                        pending_input_name: "one".into(),
                        expression: before_one,
                    },
                    TypedGuard {
                        pending_input_name: "pending".into(),
                        expression: after_one,
                    },
                ],
            };
        }
        _ => unreachable!("versioned family"),
    };
    RuleTree {
        source: TypedSource::Expression(expression),
        guards: vec![],
    }
}

const ERROR_FAMILIES: &[&str] = &[
    "error-empty-extremum",
    "error-mixed-extremum",
    "error-nan-extremum",
    "error-numeric-cast",
    "error-duration-boundary",
    "error-timestamp-boundary",
    "error-aggregate-map-key",
    "error-list-index-kind",
    "error-missing-field",
    "error-temporal-parse",
    "error-list-map-add",
    "error-invalid-operator-kind",
];
fn error_tree(rng: &mut Random, index: usize) -> (RuleTree, &'static str, &'static str) {
    let family = ERROR_FAMILIES[index % ERROR_FAMILIES.len()];
    let scope = Scope::root();
    let error = match family {
        "error-empty-extremum" => {
            let ty = numeric_type(rng);
            let values = list(ty.clone(), vec![]);
            if rng.pick(2) == 0 {
                call(ty, "min", None, vec![values])
            } else {
                call(ty, "max", Some(values), vec![])
            }
        }
        "error-mixed-extremum" => {
            let nan = call(Type::Double, "double", None, vec![text("NaN")]);
            let mut values = vec![literal_number(rng, &Type::Int), nan];
            if rng.pick(2) == 0 {
                values.reverse();
            }
            call(Type::Int, "min", None, vec![list(Type::Any, values)])
        }
        "error-nan-extremum" => {
            let nan = call(Type::Double, "double", None, vec![text("NaN")]);
            call(
                Type::Double,
                "max",
                Some(list(
                    Type::Double,
                    vec![literal_number(rng, &Type::Double), nan],
                )),
                vec![],
            )
        }
        "error-numeric-cast" => {
            if rng.pick(2) == 0 {
                call(Type::Int, "int", None, vec![text("bad-number")])
            } else {
                call(Type::UInt, "uint", None, vec![int(-1)])
            }
        }
        "error-duration-boundary" => {
            let max = call(
                Type::Duration,
                "duration",
                None,
                vec![text("9223372036854775807ms")],
            );
            let tick = call(Type::Duration, "duration", None, vec![text("1ms")]);
            binary(Type::Duration, Binary::Add, max, tick)
        }
        "error-timestamp-boundary" => {
            let max = call(
                Type::Timestamp,
                "timestamp",
                None,
                vec![text("9999-12-31T23:59:59Z")],
            );
            let tick = call(Type::Duration, "duration", None, vec![text("1s")]);
            binary(Type::Timestamp, Binary::Add, max, tick)
        }
        "error-aggregate-map-key" => map(vec![(list(Type::Int, vec![int(1)]), int(0))]),
        "error-list-index-kind" => ast(
            Type::Int,
            Node::Index {
                target: Box::new(list(Type::Int, vec![int(0), int(1)])),
                index: Box::new(boolean(true)),
            },
        ),
        "error-missing-field" => select(global("one", Type::Row), "absent", Type::Any),
        "error-temporal-parse" => call(Type::Duration, "duration", None, vec![text("1s!")]),
        // Final repaired semantics, intentionally never executed as a semantic
        // assertion against the inherited runtime in this leaf.
        "error-list-map-add" => {
            let (left, right) = match rng.pick(3) {
                0 => (list(Type::Row, vec![]), global("one", Type::Row)),
                1 => (global("xs", list_type(Type::Row)), global("one", Type::Row)),
                _ => (list(Type::Any, vec![]), map(vec![(text("a"), text(""))])),
            };
            binary(Type::Any, Binary::Add, left, right)
        }
        "error-invalid-operator-kind" => {
            let (op, left, right) = match rng.pick(4) {
                0 => (Binary::Add, global("one", Type::Row), int(1)),
                1 => (Binary::Subtract, boolean(true), int(1)),
                2 => (Binary::Multiply, text("abc"), boolean(false)),
                _ => (Binary::Subtract, list(Type::Int, vec![int(1)]), int(1)),
            };
            binary(Type::Any, op, left, right)
        }
        _ => unreachable!(),
    };
    let category = match family {
        "error-mixed-extremum" | "error-list-map-add" => "NoSuchOverload",
        "error-invalid-operator-kind" => "UnsupportedBinaryOperator",
        "error-duration-boundary" | "error-timestamp-boundary" => "Overflow",
        "error-aggregate-map-key" => "UnsupportedKeyType",
        "error-list-index-kind" => "UnexpectedType",
        "error-missing-field" => "NoSuchKey",
        _ => "FunctionError",
    };
    // The successful prelude is evaluated before the error. Its recursive tree
    // changes the error-prefix path, not merely the final literal spelling.
    let depth = 3 + rng.pick(2);
    let prefix = scalar_tree(rng, depth, &scope);
    let output = map(vec![(text("prefix"), prefix), (text("error"), error)]);
    (
        RuleTree {
            source: TypedSource::Expression(output),
            guards: vec![],
        },
        family,
        category,
    )
}

fn quote(value: &str) -> String {
    serde_json::to_string(value).expect("string encoding")
}
impl Ast {
    pub(crate) fn source(&self) -> String {
        match &self.node {
            Node::Literal(value) => match value {
                Literal::Int(n) => {
                    if *n < 0 {
                        format!("({n})")
                    } else {
                        n.to_string()
                    }
                }
                Literal::UInt(n) => format!("{n}u"),
                Literal::Double(n) => n.clone(),
                Literal::Bool(v) => v.to_string(),
                Literal::Text(s) => quote(s),
                Literal::Bytes(s) => format!("b{}", quote(s)),
            },
            Node::Variable(Variable::Global(name) | Variable::Bound { name, .. }) => name.clone(),
            Node::Select { target, field } => format!("{}.{field}", target.source()),
            Node::Index { target, index } => format!("{}[{}]", target.source(), index.source()),
            Node::Unary { op, value } => format!(
                "({}{})",
                match op {
                    Unary::Not => "!",
                    Unary::Negate => "-",
                },
                value.source()
            ),
            Node::Binary { op, left, right } => format!(
                "({} {} {})",
                left.source(),
                match op {
                    Binary::Add => "+",
                    Binary::Subtract => "-",
                    Binary::Multiply => "*",
                    Binary::Divide => "/",
                    Binary::Equal => "==",
                    Binary::NotEqual => "!=",
                    Binary::Less => "<",
                    Binary::LessEqual => "<=",
                    Binary::Greater => ">",
                    Binary::GreaterEqual => ">=",
                    Binary::And => "&&",
                    Binary::Or => "||",
                    Binary::In => "in",
                },
                right.source()
            ),
            Node::Conditional { condition, yes, no } => format!(
                "({} ? {} : {})",
                condition.source(),
                yes.source(),
                no.source()
            ),
            Node::Call {
                name,
                receiver,
                args,
            } => {
                let args = args.iter().map(Ast::source).collect::<Vec<_>>().join(",");
                match receiver {
                    Some(target) => format!("{}.{name}({args})", target.source()),
                    None => format!("{name}({args})"),
                }
            }
            Node::List(entries) => format!(
                "[{}]",
                entries
                    .iter()
                    .map(Ast::source)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Node::Map(entries) => format!(
                "{{{}}}",
                entries
                    .iter()
                    .map(|(k, v)| format!("{}:{}", k.source(), v.source()))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Node::Macro {
                kind,
                range,
                variable,
                body,
                predicate,
            } => {
                let name = match kind {
                    Macro::Map | Macro::MapThree => "map",
                    Macro::Filter => "filter",
                    Macro::All => "all",
                    Macro::Exists => "exists",
                    Macro::ExistsOne => "exists_one",
                };
                let body = if let Some(p) = predicate {
                    format!("{},{}", p.source(), body.source())
                } else {
                    body.source()
                };
                format!("{}.{name}({variable},{body})", range.source())
            }
        }
    }
    fn children(&self) -> Vec<&Ast> {
        match &self.node {
            Node::Literal(_) | Node::Variable(_) => vec![],
            Node::Select { target, .. } | Node::Unary { value: target, .. } => vec![target],
            Node::Index { target, index } => vec![target, index],
            Node::Binary { left, right, .. } => vec![left, right],
            Node::Conditional { condition, yes, no } => vec![condition, yes, no],
            Node::Call { receiver, args, .. } => receiver
                .iter()
                .map(|r| r.as_ref())
                .chain(args.iter())
                .collect(),
            Node::List(entries) => entries.iter().collect(),
            Node::Map(entries) => entries.iter().flat_map(|(k, v)| [k, v]).collect(),
            Node::Macro {
                range,
                body,
                predicate,
                ..
            } => vec![range.as_ref(), body.as_ref()]
                .into_iter()
                .chain(predicate.iter().map(|p| p.as_ref()))
                .collect(),
        }
    }
    fn fingerprint(&self, structural: bool) -> String {
        let tag = match &self.node {
            Node::Literal(v) => {
                if structural {
                    match v {
                        Literal::Int(_) => "lit-int".into(),
                        Literal::UInt(_) => "lit-uint".into(),
                        Literal::Double(_) => "lit-double".into(),
                        Literal::Bool(_) => "lit-bool".into(),
                        Literal::Text(_) => "lit-text".into(),
                        Literal::Bytes(_) => "lit-bytes".into(),
                    }
                } else {
                    format!("literal:{v:?}")
                }
            }
            Node::Variable(Variable::Global(name)) => format!("free:{}", quote(name)),
            Node::Variable(Variable::Bound { distance, .. }) => format!("bound:{distance}"),
            Node::Select { field, .. } => format!("field:{}", quote(field)),
            Node::Index { .. } => "index".into(),
            Node::Unary { op, .. } => format!("unary:{op:?}"),
            Node::Binary { op, .. } => format!("binary:{op:?}"),
            Node::Conditional { .. } => "conditional".into(),
            Node::Call { name, receiver, .. } => format!(
                "call:{}:{}",
                quote(name),
                if receiver.is_some() {
                    "receiver"
                } else {
                    "global"
                }
            ),
            Node::List(_) => "list".into(),
            Node::Map(_) => "map".into(),
            Node::Macro { kind, .. } => format!("macro:{kind:?}"),
        };
        // Length-prefixed tags/children make serialization unambiguous even if a
        // literal contains punctuation from the fingerprint grammar.
        let children = self
            .children()
            .into_iter()
            .map(|c| c.fingerprint(structural))
            .collect::<Vec<_>>();
        let tag = format!("{:?}:{tag}", self.ty);
        format!(
            "{}:{tag}[{}]",
            tag.len(),
            children
                .into_iter()
                .map(|c| format!("{}:{c}", c.len()))
                .collect::<String>()
        )
    }
    fn summary(&self) -> (usize, usize, usize, BTreeMap<String, usize>) {
        let mut nodes = 1;
        let mut depth = if matches!(&self.node,Node::Literal(Literal::Int(n)) if *n<0) {
            2
        } else {
            1
        };
        let mut bodies = 0;
        let mut features = BTreeMap::new();
        let tag = match &self.node {
            Node::Literal(v) => format!(
                "literal:{:?}",
                match v {
                    Literal::Int(_) => Type::Int,
                    Literal::UInt(_) => Type::UInt,
                    Literal::Double(_) => Type::Double,
                    Literal::Bool(_) => Type::Bool,
                    Literal::Text(_) => Type::Text,
                    Literal::Bytes(_) => Type::Bytes,
                }
            ),
            Node::Variable(Variable::Bound { .. }) => "bound-variable".into(),
            Node::Variable(_) => "free-variable".into(),
            Node::Select { .. } => "select".into(),
            Node::Index { .. } => "index".into(),
            Node::Unary { op, .. } => format!("unary:{op:?}"),
            Node::Binary { op, .. } => format!("binary:{op:?}"),
            Node::Conditional { .. } => "conditional".into(),
            Node::Call { name, receiver, .. } => format!(
                "call:{name}:{}",
                if receiver.is_some() {
                    "receiver"
                } else {
                    "global"
                }
            ),
            Node::List(_) => "list".into(),
            Node::Map(_) => "map".into(),
            Node::Macro { kind, .. } => format!("macro:{kind:?}"),
        };
        features.insert(tag, 1);
        if let Node::Binary { op, left, right } = &self.node {
            features.insert(format!("operator:{op:?}:{:?}:{:?}", left.ty, right.ty), 1);
        }
        if let Node::Macro { range, .. } = &self.node {
            if let Type::KeyMap(kind) = &range.ty {
                features.insert(format!("key-iteration:{kind:?}"), 1);
            }
        }
        if let Node::Call { name, receiver, .. } = &self.node {
            if matches!(name.as_str(), "min" | "max") {
                features.insert(
                    format!(
                        "extremum:{name}:{}:{:?}",
                        if receiver.is_some() {
                            "receiver"
                        } else {
                            "global"
                        },
                        self.ty
                    ),
                    1,
                );
            }
        }
        for (i, child) in self.children().into_iter().enumerate() {
            let (n, d, b, f) = child.summary();
            nodes += n;
            // Every current macro expansion adds <=4 edges on any user-body
            // path and <=4 independent synthetic depth. Range nesting is
            // sequential: only body/predicate increases comp-body nesting.
            let macro_body = matches!(self.node, Node::Macro { .. }) && i > 0;
            depth = depth.max(d + if macro_body { 4 } else { 1 });
            bodies = bodies.max(b + usize::from(macro_body));
            for (key, count) in f {
                *features.entry(key).or_insert(0) += count;
            }
        }
        if matches!(self.node, Node::Macro { .. }) {
            depth = depth.max(5);
            bodies = bodies.max(1);
        }
        (nodes, depth, bodies, features)
    }
}
impl RuleTree {
    fn expressions(&self) -> Vec<&Ast> {
        let mut expressions = match &self.source {
            TypedSource::Expression(e) => vec![e],
            TypedSource::Clauses(c) => c.iter().flat_map(|c| [&c.when, &c.result]).collect(),
        };
        expressions.extend(self.guards.iter().map(|g| &g.expression));
        expressions
    }
    pub(crate) fn fingerprint(&self, structural: bool) -> String {
        let mut parts = vec![match &self.source {
            TypedSource::Expression(_) => "expression".into(),
            TypedSource::Clauses(c) => format!("clauses:{}", c.len()),
        }];
        // Clause IDs/fixture names are deliberately absent. Ordering is retained.
        match &self.source {
            TypedSource::Expression(e) => parts.push(e.fingerprint(structural)),
            TypedSource::Clauses(c) => {
                for c in c {
                    parts.push(c.when.fingerprint(structural));
                    parts.push(c.result.fingerprint(structural));
                }
            }
        }
        for guard in &self.guards {
            parts.push(format!("guard:{}", quote(&guard.pending_input_name)));
            parts.push(guard.expression.fingerprint(structural));
        }
        parts
            .into_iter()
            .map(|p| format!("{}:{p}", p.len()))
            .collect()
    }
    fn metadata(&self, family: &'static str, error: bool) -> Metadata {
        let mut result = Metadata {
            family,
            output_types: match &self.source {
                TypedSource::Expression(e) => vec![e.ty.clone()],
                TypedSource::Clauses(c) => c.iter().map(|c| c.result.ty.clone()).collect(),
            },
            nodes: 0,
            expanded_depth_bound: 0,
            comprehension_body_depth: 0,
            features: BTreeMap::new(),
            intentional_semantic_error: error,
        };
        for e in self.expressions() {
            let (nodes, depth, bodies, features) = e.summary();
            result.nodes += nodes;
            result.expanded_depth_bound = result.expanded_depth_bound.max(depth);
            result.comprehension_body_depth = result.comprehension_body_depth.max(bodies);
            for (key, count) in features {
                *result.features.entry(key).or_insert(0) += count;
            }
        }
        result
    }
    fn sources(&self) -> Vec<String> {
        self.expressions().into_iter().map(Ast::source).collect()
    }
}
pub(crate) fn fingerprint_hash(bytes: &str) -> u64 {
    bytes.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, b| {
        (hash ^ b as u64).wrapping_mul(0x100_0000_01b3)
    })
}

fn declarations() -> Vec<InputDecl> {
    // Fixed domain, independent of generated/sample values. Row field labels in
    // the typed grammar are SQL/domain labels; InputDecl adds no registry schema.
    let mut entries = [
        ("xs", InputKind::Many),
        ("ys", InputKind::Many),
        ("one", InputKind::One),
        ("pending", InputKind::One),
    ]
    .into_iter()
    .map(|(name, kind)| InputDecl {
        name: name.into(),
        kind,
    })
    .collect::<Vec<_>>();
    for (name, kind) in [
        ("n", ScalarType::Int),
        ("m", ScalarType::Int),
        ("flag", ScalarType::Bool),
        ("text", ScalarType::String),
        ("now_ms", ScalarType::Int),
    ] {
        entries.push(InputDecl {
            name: name.into(),
            kind: InputKind::Scalar {
                kind,
                nullable: false,
            },
        });
    }
    entries
}
fn row_value(i: usize) -> Value {
    Value::from(IndexMap::from([
        ("id".to_string(), Value::from(format!("g{i}"))),
        ("n".into(), Value::Int(i as i64 + 1)),
        ("ok".into(), Value::Bool(i.is_multiple_of(2))),
        (
            "body".into(),
            Value::from(if i.is_multiple_of(2) { "alpha" } else { "beta" }),
        ),
    ]))
}
fn scenarios(expected: Expected) -> Vec<Scenario> {
    [0,1,4,16].into_iter().map(|count|Scenario {
        name:format!("rows-{count}"),bindings:vec![
            ("xs".into(),Value::from((0..count).map(row_value).collect::<Vec<_>>())),
            ("ys".into(),Value::from((0..count).map(row_value).rev().collect::<Vec<_>>())),
            ("one".into(),row_value(2)),("pending".into(),Value::Null),
            ("n".into(),Value::Int(3)),("m".into(),Value::Int(2)),
            ("flag".into(),Value::Bool(count%2==0)),("text".into(),Value::from("alpha")),
            ("now_ms".into(),Value::Int(1_700_000_000_000)),
        ],expected,adapter_expected:None,
        notes:"Fixed scalar-row domain; binding samples do not determine admission bounds. Empty/one/four/sixteen Many rows. Pending null One is excluded from its guard prefix.".into(),
    }).collect()
}
fn fixture(
    tree: &RuleTree,
    family: &'static str,
    attempt: usize,
    pool: &[Scenario],
    expected: Expected,
) -> Fixture {
    let source = match &tree.source {
        TypedSource::Expression(e) => Source::Expression(e.source()),
        TypedSource::Clauses(clauses) => Source::Clauses(
            clauses
                .iter()
                .enumerate()
                .map(|(i, c)| Clause {
                    id: format!("clause{i}"),
                    when: c.when.source(),
                    result: c.result.source(),
                })
                .collect(),
        ),
    };
    let mut samples = pool.to_vec();
    for sample in &mut samples {
        sample.expected = expected;
    }
    Fixture {
        name: format!("generated-{attempt}"),
        family,
        source,
        declarations: declarations(),
        scenarios: samples,
        guards: tree
            .guards
            .iter()
            .map(|g| GuardDescriptor {
                pending_input_name: g.pending_input_name.clone(),
                source: g.expression.source(),
            })
            .collect(),
        input_metadata: vec![],
    }
}

/// Requested count refers to successful, structurally distinct candidates.
/// Extra intentionally erroneous rules are separate and never fill that quota.
/// No policy/API rejection sampling occurs. Grammar/duplicate retries are fully
/// counted and the bounded attempt budget can return an explicitly incomplete set.
pub(crate) fn generate(seed: u64, requested_successes: usize) -> GeneratedSet {
    let mut rng = Random(seed);
    let mut rules = vec![];
    let mut counts = Counts {
        requested_successes,
        ..Counts::default()
    };
    let mut canonical = BTreeSet::new();
    let mut structural = BTreeSet::new();
    let pool = scenarios(Expected::AdmitValue);
    let mut successes_attempted = 0;
    let mut errors_attempted = 0;
    let budget = requested_successes.saturating_mul(32).saturating_add(100);
    while counts.successful_candidates < requested_successes && counts.attempts < budget {
        let attempt = counts.attempts;
        counts.attempts += 1;
        let is_error = attempt % 6 == 5;
        let (tree, family, expected) = if is_error {
            let (tree, family, category) = error_tree(&mut rng, errors_attempted);
            errors_attempted += 1;
            (tree, family, Expected::AdmitSemanticError(category))
        } else {
            let family = FAMILIES[successes_attempted % FAMILIES.len()];
            successes_attempted += 1;
            (success_tree(&mut rng, family), family, Expected::AdmitValue)
        };
        *counts.attempted_by_family.entry(family.into()).or_insert(0) += 1;
        let metadata = tree.metadata(family, is_error);
        if metadata.nodes > NODE_BOUND
            || metadata.expanded_depth_bound > DEPTH_BOUND
            || metadata.comprehension_body_depth > 2
            || tree.sources().iter().any(|s| s.len() > SOURCE_BOUND)
        {
            counts.grammar_limit_rejections += 1;
            counts.retries += 1;
            continue;
        }
        let canonical_fingerprint = tree.fingerprint(false);
        let structural_fingerprint = tree.fingerprint(true);
        let canonical_duplicate = canonical.contains(&canonical_fingerprint);
        let structural_duplicate = structural.contains(&structural_fingerprint);
        counts.canonical_duplicates += usize::from(canonical_duplicate);
        counts.structural_duplicates += usize::from(structural_duplicate);
        if canonical_duplicate || structural_duplicate {
            counts.retries += 1;
            continue;
        }
        canonical.insert(canonical_fingerprint.clone());
        structural.insert(structural_fingerprint.clone());
        counts.generated_candidates += 1;
        if is_error {
            counts.semantic_error_candidates += 1;
        } else {
            counts.successful_candidates += 1;
        }
        *counts.generated_by_family.entry(family.into()).or_insert(0) += 1;
        for ty in &metadata.output_types {
            *counts
                .generated_by_output_type
                .entry(format!("{ty:?}"))
                .or_insert(0) += 1;
        }
        for (key, value) in &metadata.features {
            *counts.features.entry(key.clone()).or_insert(0) += value;
        }
        let canonical_hash = fingerprint_hash(&canonical_fingerprint);
        let structural_hash = fingerprint_hash(&structural_fingerprint);
        rules.push(GeneratedRule {
            fixture: fixture(&tree, family, attempt, &pool, expected),
            tree,
            metadata,
            canonical_fingerprint,
            structural_fingerprint,
            canonical_hash,
            structural_hash,
            attempt,
        });
    }
    counts.exhausted_attempt_budget = counts.successful_candidates < requested_successes;
    GeneratedSet {
        seed,
        version: GENERATOR_VERSION,
        counts,
        rules,
    }
}

/// Separate refusal corpus; never included in generate's successful count.
pub(crate) fn refusal_samples(seed: u64, count: usize) -> Vec<GeneratedRule> {
    let mut rng = Random(seed);
    let scope = Scope::root();
    let pool = scenarios(Expected::Refuse("many-cross-product"));
    (0..count)
        .map(|attempt| {
            let outer = scope.bind("x", Type::Row, true);
            let inner = outer.bind("y", Type::Row, true);
            let a = number(&mut rng, Type::Int, 3, &inner);
            let b = select(outer.local(&Type::Row).unwrap(), "n", Type::Int);
            // Rebase captured x to distance 1 in the nested y scope.
            let b = match b.node {
                Node::Select { field, .. } => select(
                    ast(
                        Type::Row,
                        Node::Variable(Variable::Bound {
                            name: "x".into(),
                            distance: 1,
                        }),
                    ),
                    &field,
                    Type::Int,
                ),
                _ => unreachable!(),
            };
            let test = binary(Type::Bool, Binary::Equal, a, b);
            let inner_range = global(
                if attempt % 2 == 0 { "ys" } else { "xs" },
                list_type(Type::Row),
            );
            let inner = macro_expr(Macro::Exists, inner_range, "y", test, None);
            let output = macro_expr(
                Macro::All,
                global("xs", list_type(Type::Row)),
                "x",
                inner,
                None,
            );
            let tree = RuleTree {
                source: TypedSource::Expression(output),
                guards: vec![],
            };
            let metadata = tree.metadata("generated-cross-product-refusal", false);
            let canonical_fingerprint = tree.fingerprint(false);
            let structural_fingerprint = tree.fingerprint(true);
            GeneratedRule {
                fixture: fixture(
                    &tree,
                    metadata.family,
                    attempt,
                    &pool,
                    Expected::Refuse("many-cross-product"),
                ),
                canonical_hash: fingerprint_hash(&canonical_fingerprint),
                structural_hash: fingerprint_hash(&structural_fingerprint),
                canonical_fingerprint,
                structural_fingerprint,
                tree,
                metadata,
                attempt,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;
    fn corpus() -> &'static GeneratedSet {
        static SET: OnceLock<GeneratedSet> = OnceLock::new();
        SET.get_or_init(|| generate(DEFAULT_SEED, 10_000))
    }
    fn globals() -> BTreeMap<String, Type> {
        declarations()
            .into_iter()
            .map(|d| {
                (
                    d.name,
                    match d.kind {
                        InputKind::One => Type::Row,
                        InputKind::Many => list_type(Type::Row),
                        InputKind::Scalar { kind, .. } => match kind {
                            ScalarType::Int => Type::Int,
                            ScalarType::Double => Type::Double,
                            ScalarType::Bool => Type::Bool,
                            ScalarType::String => Type::Text,
                            ScalarType::Any => Type::Any,
                        },
                    },
                )
            })
            .collect()
    }
    // Independent well-typed tree validation. Intentionally invalid overloads
    // retain operand types and are permitted only in the explicit error set.
    fn typed(
        e: &Ast,
        globals: &BTreeMap<String, Type>,
        locals: &mut Vec<(String, Type)>,
        error: bool,
    ) {
        match &e.node {
            Node::Variable(Variable::Global(name)) => assert_eq!(globals.get(name), Some(&e.ty)),
            Node::Variable(Variable::Bound { name, distance }) => {
                let slot = &locals[locals.len() - 1 - distance];
                assert_eq!(&slot.0, name);
                assert_eq!(slot.1, e.ty);
                assert_eq!(
                    locals.iter().rev().position(|(n, _)| n == name),
                    Some(*distance),
                    "shadowed reference"
                );
            }
            Node::Literal(v) => assert_eq!(
                e.ty,
                match v {
                    Literal::Int(_) => Type::Int,
                    Literal::UInt(_) => Type::UInt,
                    Literal::Double(_) => Type::Double,
                    Literal::Bool(_) => Type::Bool,
                    Literal::Text(_) => Type::Text,
                    Literal::Bytes(_) => Type::Bytes,
                }
            ),
            Node::Select { target, field } => {
                typed(target, globals, locals, error);
                assert_eq!(target.ty, Type::Row);
                let ty = match field.as_str() {
                    "n" => Type::Int,
                    "ok" => Type::Bool,
                    "id" | "body" => Type::Text,
                    "absent" if error => Type::Any,
                    _ => panic!("unknown domain field"),
                };
                assert_eq!(e.ty, ty);
            }
            Node::Index { target, index } => {
                typed(target, globals, locals, error);
                typed(index, globals, locals, error);
                let Type::List(element) = &target.ty else {
                    panic!("list index")
                };
                assert_eq!(&e.ty, element.as_ref());
                assert!(error || matches!(index.ty, Type::Int | Type::UInt));
            }
            Node::Unary { op, value } => {
                typed(value, globals, locals, error);
                assert_eq!(e.ty, value.ty);
                match op {
                    Unary::Not => assert_eq!(e.ty, Type::Bool),
                    Unary::Negate => assert!(matches!(e.ty, Type::Int | Type::Double)),
                }
            }
            Node::Binary { op, left, right } => {
                typed(left, globals, locals, error);
                typed(right, globals, locals, error);
                if error && e.ty == Type::Any {
                    return;
                }
                match op {
                    Binary::And | Binary::Or => {
                        assert_eq!(e.ty, Type::Bool);
                        assert_eq!(left.ty, Type::Bool);
                        assert_eq!(right.ty, Type::Bool);
                    }
                    Binary::In => {
                        assert_eq!(e.ty, Type::Bool);
                        assert_eq!(right.ty, list_type(left.ty.clone()));
                    }
                    Binary::Equal
                    | Binary::NotEqual
                    | Binary::Less
                    | Binary::LessEqual
                    | Binary::Greater
                    | Binary::GreaterEqual => {
                        assert_eq!(e.ty, Type::Bool);
                        assert_eq!(left.ty, right.ty);
                    }
                    Binary::Add if left.ty == Type::Timestamp => {
                        assert_eq!(e.ty, Type::Timestamp);
                        assert_eq!(right.ty, Type::Duration);
                    }
                    _ => {
                        assert_eq!(left.ty, right.ty);
                        assert_eq!(e.ty, left.ty);
                    }
                }
            }
            Node::Conditional { condition, yes, no } => {
                for c in [condition, yes, no] {
                    typed(c, globals, locals, error);
                }
                assert_eq!(condition.ty, Type::Bool);
                assert_eq!(yes.ty, no.ty);
                assert_eq!(e.ty, yes.ty);
            }
            Node::List(entries) => {
                let Type::List(kind) = &e.ty else {
                    panic!("list type")
                };
                for child in entries {
                    typed(child, globals, locals, error);
                    assert!(kind.as_ref() == &Type::Any && error || kind.as_ref() == &child.ty);
                }
            }
            Node::Map(entries) => {
                assert!(matches!(e.ty, Type::Map | Type::KeyMap(_)));
                for (key, value) in entries {
                    if let Type::KeyMap(kind) = &e.ty {
                        assert!(kind.as_ref() == &Type::Any || kind.as_ref() == &key.ty);
                    }
                    typed(key, globals, locals, error);
                    typed(value, globals, locals, error);
                    assert!(
                        error || matches!(key.ty, Type::Int | Type::UInt | Type::Bool | Type::Text)
                    );
                }
            }
            Node::Macro {
                kind,
                range,
                variable,
                body,
                predicate,
            } => {
                typed(range, globals, locals, error);
                let element = match &range.ty {
                    Type::List(element) | Type::KeyMap(element) => element,
                    _ => panic!("macro range"),
                };
                locals.push((variable.clone(), element.as_ref().clone()));
                typed(body, globals, locals, error);
                if let Some(p) = predicate {
                    typed(p, globals, locals, error);
                    assert_eq!(p.ty, Type::Bool);
                }
                locals.pop();
                match kind {
                    Macro::All | Macro::Exists | Macro::ExistsOne => {
                        assert_eq!(body.ty, Type::Bool);
                        assert_eq!(e.ty, Type::Bool);
                        assert!(predicate.is_none());
                    }
                    Macro::Filter => {
                        assert_eq!(body.ty, Type::Bool);
                        assert_eq!(e.ty, range.ty);
                        assert!(predicate.is_none());
                    }
                    Macro::Map | Macro::MapThree => {
                        assert_eq!(e.ty, list_type(body.ty.clone()));
                        assert_eq!(predicate.is_some(), *kind == Macro::MapThree);
                    }
                }
            }
            Node::Call {
                name,
                receiver,
                args,
            } => {
                for child in e.children() {
                    typed(child, globals, locals, error);
                }
                let logical = receiver
                    .iter()
                    .map(|r| r.as_ref())
                    .chain(args.iter())
                    .collect::<Vec<_>>();
                match name.as_str() {
                    "size" => {
                        assert_eq!(logical.len(), 1);
                        assert_eq!(e.ty, Type::Int);
                        assert!(matches!(
                            logical[0].ty,
                            Type::List(_)
                                | Type::Map
                                | Type::KeyMap(_)
                                | Type::Row
                                | Type::Text
                                | Type::Bytes
                        ));
                    }
                    "min" | "max" => {
                        assert_eq!(logical.len(), 1);
                        let Type::List(element) = &logical[0].ty else {
                            panic!("extremum list")
                        };
                        assert!(
                            error && element.as_ref() == &Type::Any || element.as_ref() == &e.ty
                        );
                        assert!(matches!(e.ty, Type::Int | Type::UInt | Type::Double));
                    }
                    "int" | "uint" | "double" => {
                        assert!(receiver.is_none());
                        assert_eq!(args.len(), 1);
                        assert!(matches!(
                            args[0].ty,
                            Type::Int | Type::UInt | Type::Double | Type::Text
                        ));
                        assert_eq!(
                            e.ty,
                            match name.as_str() {
                                "int" => Type::Int,
                                "uint" => Type::UInt,
                                _ => Type::Double,
                            }
                        );
                    }
                    "dyn" => {
                        assert!(receiver.is_none());
                        assert_eq!(args.len(), 1);
                        assert_eq!(e.ty, args[0].ty);
                    }
                    "string" => {
                        assert!(receiver.is_none());
                        assert_eq!(args.len(), 1);
                        assert!(matches!(
                            args[0].ty,
                            Type::Int
                                | Type::UInt
                                | Type::Double
                                | Type::Text
                                | Type::Bytes
                                | Type::Duration
                                | Type::Timestamp
                        ));
                        assert_eq!(e.ty, Type::Text);
                    }
                    "bytes" => {
                        assert!(receiver.is_none());
                        assert_eq!(args.len(), 1);
                        assert!(matches!(args[0].ty, Type::Text | Type::Bytes));
                        assert_eq!(e.ty, Type::Bytes);
                    }
                    "duration" | "timestamp" => {
                        assert!(receiver.is_none());
                        assert_eq!(args.len(), 1);
                        let ty = if name == "duration" {
                            Type::Duration
                        } else {
                            Type::Timestamp
                        };
                        assert!(args[0].ty == Type::Text || args[0].ty == ty);
                        assert_eq!(e.ty, ty);
                    }
                    "contains" => {
                        assert_eq!(e.ty, Type::Bool);
                        assert!(receiver.is_some());
                        assert_eq!(args.len(), 1);
                        match &receiver.as_ref().unwrap().ty {
                            Type::Text => assert_eq!(args[0].ty, Type::Text),
                            Type::List(ty) => assert_eq!(ty.as_ref(), &args[0].ty),
                            _ => panic!("contains receiver"),
                        }
                    }
                    "startsWith" | "endsWith" | "matches" => {
                        assert_eq!(e.ty, Type::Bool);
                        assert_eq!(logical.len(), 2);
                        for a in logical {
                            assert_eq!(a.ty, Type::Text);
                        }
                        if name != "matches" {
                            assert!(receiver.is_some());
                        }
                    }
                    other => panic!("unrecognized call {other}"),
                }
            }
        }
    }

    #[test]
    fn stable_seed_version_and_fingerprints() {
        assert_eq!(GENERATOR_VERSION, "native-typed-grammar-v2");
        let mut rng = Random(0);
        assert_eq!(rng.next(), 0xe220_a839_7b1d_cdaf);
        assert_eq!(fingerprint_hash("hello"), 0xa430_d846_80aa_bd0b);
        let a = generate(DEFAULT_SEED, 64);
        let b = generate(DEFAULT_SEED, 64);
        assert_eq!(
            a.rules
                .iter()
                .take(4)
                .map(|r| (r.canonical_hash, r.structural_hash))
                .collect::<Vec<_>>(),
            [
                (3931038085149141406, 15723160414838665594),
                (10650051138248407513, 14575244130736429668),
                (16878262806692472165, 3601392306453853540),
                (381179165389824144, 16136646521063186429),
            ]
        );
        assert_eq!(a.counts.generated_candidates, 76);
        assert_eq!(a.counts.attempts, 76);
        assert_eq!(a.counts.retries, 0);
        assert_eq!(a.version, b.version);
        assert_eq!(a.seed, b.seed);
        assert_eq!(a.counts, b.counts);
        assert_eq!(
            a.rules
                .iter()
                .map(|r| (&r.canonical_fingerprint, &r.structural_fingerprint))
                .collect::<Vec<_>>(),
            b.rules
                .iter()
                .map(|r| (&r.canonical_fingerprint, &r.structural_fingerprint))
                .collect::<Vec<_>>()
        );
        let larger = generate(DEFAULT_SEED, 128);
        assert_eq!(
            a.rules
                .iter()
                .map(|r| &r.canonical_fingerprint)
                .collect::<Vec<_>>(),
            larger
                .rules
                .iter()
                .take(a.rules.len())
                .map(|r| &r.canonical_fingerprint)
                .collect::<Vec<_>>()
        );
        assert_ne!(
            a.rules[0].canonical_hash,
            generate(DEFAULT_SEED ^ 1, 64).rules[0].canonical_hash
        );
        let empty = generate(DEFAULT_SEED, 0);
        assert!(empty.rules.is_empty());
        assert_eq!(empty.counts.attempts, 0);
        assert_eq!(int(1).fingerprint(true), int(2).fingerprint(true));
        assert_ne!(int(1).fingerprint(false), int(2).fingerprint(false));
        let mut x = ast(
            Type::Int,
            Node::Variable(Variable::Bound {
                name: "x".into(),
                distance: 0,
            }),
        );
        let before = x.fingerprint(false);
        x.node = Node::Variable(Variable::Bound {
            name: "y".into(),
            distance: 0,
        });
        assert_eq!(before, x.fingerprint(false));
        assert_ne!(
            binary(Type::Int, Binary::Add, int(1), int(2)).fingerprint(true),
            binary(Type::Int, Binary::Multiply, int(1), int(2)).fingerprint(true)
        );
        println!(
            "GENERATOR_GOLDEN {:?} counts={:?}",
            a.rules
                .iter()
                .take(4)
                .map(|r| (r.canonical_hash, r.structural_hash))
                .collect::<Vec<_>>(),
            a.counts
        );
    }

    #[test]
    fn ten_thousand_structurally_distinct_and_coverage() {
        let set = corpus();
        assert_eq!(set.counts.successful_candidates, 10_000);
        assert!(!set.counts.exhausted_attempt_budget);
        assert_eq!(set.rules.len(), set.counts.generated_candidates);
        assert_eq!(
            set.counts.generated_candidates,
            10_000 + set.counts.semantic_error_candidates
        );
        assert_eq!(set.counts.attempts, set.rules.len() + set.counts.retries);
        assert_eq!(
            set.counts.attempted_by_family.values().sum::<usize>(),
            set.counts.attempts
        );
        assert_eq!(
            set.counts.generated_by_family.values().sum::<usize>(),
            set.rules.len()
        );
        let canonical = set
            .rules
            .iter()
            .map(|r| &r.canonical_fingerprint)
            .collect::<BTreeSet<_>>();
        let structural = set
            .rules
            .iter()
            .map(|r| &r.structural_fingerprint)
            .collect::<BTreeSet<_>>();
        assert_eq!(canonical.len(), set.rules.len());
        assert_eq!(structural.len(), set.rules.len());
        for family in FAMILIES.iter().chain(ERROR_FAMILIES) {
            assert!(
                set.counts
                    .generated_by_family
                    .get(*family)
                    .copied()
                    .unwrap_or(0)
                    > 100,
                "family {family}"
            );
        }
        for key in [
            "macro:Map",
            "macro:Filter",
            "macro:All",
            "macro:Exists",
            "macro:ExistsOne",
            "macro:MapThree",
            "bound-variable",
            "select",
            "map",
            "list",
            "index",
            "unary:Negate",
            "call:bytes:global",
            "call:timestamp:global",
            "call:duration:global",
            "call:matches:global",
            "call:matches:receiver",
        ] {
            assert!(
                set.counts.features.get(key).copied().unwrap_or(0) > 0,
                "feature {key}"
            );
        }
        for ty in [Type::Int, Type::UInt, Type::Double] {
            for name in ["min", "max"] {
                for form in ["global", "receiver"] {
                    let key = format!("extremum:{name}:{form}:{ty:?}");
                    assert!(
                        set.counts.features.get(&key).copied().unwrap_or(0) > 0,
                        "feature {key}"
                    );
                }
            }
        }
        for key in [
            "operator:Add:List(Row):Row",
            "operator:Add:List(Any):Map",
            "key-iteration:Int",
            "key-iteration:UInt",
            "key-iteration:Bool",
            "key-iteration:Any",
        ] {
            assert!(
                set.counts.features.get(key).copied().unwrap_or(0) > 0,
                "new feature {key}"
            );
        }
        let list_map_rules = set
            .rules
            .iter()
            .filter(|r| r.metadata.family == "error-list-map-add");
        let mut forms = BTreeSet::new();
        for r in list_map_rules {
            assert!(r
                .fixture
                .scenarios
                .iter()
                .all(|s| s.expected == Expected::AdmitSemanticError("NoSuchOverload")));
            let TypedSource::Expression(Ast {
                node: Node::Map(entries),
                ..
            }) = &r.tree.source
            else {
                panic!()
            };
            forms.insert(entries[1].1.source());
        }
        assert!(forms.contains("([] + one)"));
        assert!(forms.contains("(xs + one)"));
        assert!(forms.contains("([] + {\"a\":\"\"})"));
        let digest = set.rules.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, r| {
            fingerprint_hash(&format!(
                "{h:016x}:{:016x}:{:016x}",
                r.canonical_hash, r.structural_hash
            ))
        });
        assert_eq!(
            digest, 0x7543_97ba_168f_6cd5,
            "change generator version when canonical grammar output changes"
        );
        println!(
            "GENERATOR_COUNTS {:?}\nGENERATOR_CORPUS_DIGEST {digest:016x}",
            set.counts
        );
    }

    fn guard_prefixes(declarations: &[InputDecl], guards: &[TypedGuard]) -> Result<(), String> {
        let mut previous = None;
        for guard in guards {
            let pos = declarations
                .iter()
                .position(|d| d.name == guard.pending_input_name)
                .ok_or_else(|| format!("missing guard target {}", guard.pending_input_name))?;
            if declarations[pos].kind != InputKind::One {
                return Err("guard target must be One".into());
            }
            if previous.is_some_and(|prior| prior >= pos) {
                return Err("guard target order must increase".into());
            }
            previous = Some(pos);
            let allowed = declarations
                .iter()
                .enumerate()
                .filter(|(i, d)| *i < pos || matches!(d.kind, InputKind::Scalar { .. }))
                .map(|(_, d)| d.name.as_str())
                .collect::<BTreeSet<_>>();
            let mut stack = vec![&guard.expression];
            while let Some(e) = stack.pop() {
                if let Node::Variable(Variable::Global(name)) = &e.node {
                    if !allowed.contains(name.as_str()) {
                        return Err(format!("pending/future/unknown global {name}"));
                    }
                }
                stack.extend(e.children());
            }
        }
        Ok(())
    }

    #[test]
    fn typed_schema_order_and_guard_prefix() {
        let set = corpus();
        let global_types = globals();
        let expected_order = [
            "xs", "ys", "one", "pending", "n", "m", "flag", "text", "now_ms",
        ];
        for rule in &set.rules {
            assert_eq!(
                rule.fixture
                    .declarations
                    .iter()
                    .map(|d| d.name.as_str())
                    .collect::<Vec<_>>(),
                expected_order
            );
            assert!(rule.fixture.input_metadata.is_empty());
            for scenario in &rule.fixture.scenarios {
                assert_eq!(
                    scenario
                        .bindings
                        .iter()
                        .map(|(n, _)| n.as_str())
                        .collect::<Vec<_>>(),
                    expected_order
                );
                assert_eq!(
                    matches!(scenario.expected, Expected::AdmitSemanticError(_)),
                    rule.metadata.intentional_semantic_error
                );
                assert!(!matches!(scenario.expected, Expected::Refuse(_)));
                let Value::List(xs) = &scenario.bindings[0].1 else {
                    panic!()
                };
                let Value::List(ys) = &scenario.bindings[1].1 else {
                    panic!()
                };
                assert_eq!(xs.len(), ys.len());
                assert!([0, 1, 4, 16].contains(&xs.len()));
                for row in xs.iter().chain(ys.iter()) {
                    let Value::Map(row) = row else { panic!("row") };
                    assert_eq!(row.map.len(), 4);
                    assert!(row
                        .map
                        .values()
                        .all(|v| matches!(v, Value::Int(_) | Value::Bool(_) | Value::String(_))));
                }
                assert!(matches!(scenario.bindings[3].1, Value::Null));
                assert!(matches!(scenario.bindings[8].1, Value::Int(_)));
            }
            for e in rule.tree.expressions() {
                typed(
                    e,
                    &global_types,
                    &mut vec![],
                    rule.metadata.intentional_semantic_error,
                );
            }
            assert_eq!(rule.fixture.guards.len(), rule.tree.guards.len());
            guard_prefixes(&rule.fixture.declarations, &rule.tree.guards).unwrap();
            for (guard, descriptor) in rule.tree.guards.iter().zip(&rule.fixture.guards) {
                assert_eq!(guard.pending_input_name, descriptor.pending_input_name);
                assert_eq!(guard.expression.source(), descriptor.source);
                let pos = rule
                    .fixture
                    .declarations
                    .iter()
                    .position(|d| d.name == guard.pending_input_name)
                    .unwrap();
                let allowed = rule
                    .fixture
                    .declarations
                    .iter()
                    .enumerate()
                    .filter(|(i, d)| *i < pos || matches!(d.kind, InputKind::Scalar { .. }))
                    .map(|(_, d)| (d.name.clone(), global_types[&d.name].clone()))
                    .collect();
                typed(&guard.expression, &allowed, &mut vec![], false);
            }
            assert_eq!(
                rule.canonical_hash,
                fingerprint_hash(&rule.canonical_fingerprint)
            );
            assert_eq!(
                rule.structural_hash,
                fingerprint_hash(&rule.structural_fingerprint)
            );
            assert_eq!(rule.canonical_fingerprint, rule.tree.fingerprint(false));
            assert_eq!(rule.structural_fingerprint, rule.tree.fingerprint(true));
        }
        let schema = declarations();
        let guard = |target: &str, expression: Ast| TypedGuard {
            pending_input_name: target.into(),
            expression,
        };
        assert!(guard_prefixes(&schema, &[guard("absent", boolean(true))]).is_err());
        assert!(guard_prefixes(&schema, &[guard("xs", boolean(true))]).is_err());
        assert!(guard_prefixes(
            &schema,
            &[guard("pending", boolean(true)), guard("one", boolean(true))]
        )
        .is_err());
        assert!(guard_prefixes(
            &schema,
            &[guard("one", boolean(true)), guard("one", boolean(true))]
        )
        .is_err());
        assert!(guard_prefixes(
            &schema,
            &[guard(
                "one",
                select(global("one", Type::Row), "ok", Type::Bool)
            )]
        )
        .is_err());
        assert!(guard_prefixes(
            &schema,
            &[guard(
                "one",
                select(global("pending", Type::Row), "ok", Type::Bool)
            )]
        )
        .is_err());
        assert!(guard_prefixes(
            &schema,
            &[guard(
                "one",
                binary(
                    Type::Bool,
                    Binary::Greater,
                    call(
                        Type::Int,
                        "size",
                        None,
                        vec![global("xs", list_type(Type::Row))]
                    ),
                    int(0)
                )
            )]
        )
        .is_ok());
        assert!(guard_prefixes(
            &schema,
            &[
                guard("one", global("flag", Type::Bool)),
                guard(
                    "pending",
                    select(global("one", Type::Row), "ok", Type::Bool)
                )
            ]
        )
        .is_ok());
        let refuses = refusal_samples(DEFAULT_SEED, 12);
        assert_eq!(refuses.len(), 12);
        for rule in refuses {
            assert!(rule
                .fixture
                .scenarios
                .iter()
                .all(|s| matches!(s.expected, Expected::Refuse(_))));
            for e in rule.tree.expressions() {
                typed(e, &global_types, &mut vec![], false);
            }
        }
    }

    // This is generator/parser validation, not public admission or estimator
    // proof. Measure the BASE expanded AST independently; no production caps,
    // binding bypass or eval helper is exported by this data module.
    fn parsed_shape(root: &crate::IdedExpr) -> (usize, usize) {
        use crate::common::ast::{EntryExpr, Expr};
        let mut stack = vec![(root, 1usize, 0usize)];
        let mut max_depth = 0;
        let mut max_bodies = 0;
        while let Some((e, depth, bodies)) = stack.pop() {
            max_depth = max_depth.max(depth);
            max_bodies = max_bodies.max(bodies);
            let mut push = |e, body| stack.push((e, depth + 1, body));
            match &e.expr {
                Expr::Call(c) => {
                    if let Some(t) = &c.target {
                        push(t, bodies);
                    }
                    for a in &c.args {
                        push(a, bodies);
                    }
                }
                Expr::Select(s) => push(&s.operand, bodies),
                Expr::List(l) => {
                    for e in &l.elements {
                        push(e, bodies);
                    }
                }
                Expr::Map(m) => {
                    for entry in &m.entries {
                        if let EntryExpr::MapEntry(entry) = &entry.expr {
                            push(&entry.key, bodies);
                            push(&entry.value, bodies);
                        }
                    }
                }
                Expr::Comprehension(c) => {
                    push(&c.iter_range, bodies);
                    push(&c.accu_init, bodies);
                    push(&c.loop_cond, bodies + 1);
                    push(&c.loop_step, bodies + 1);
                    push(&c.result, bodies);
                }
                Expr::Ident(_) | Expr::Literal(_) => {}
                _ => panic!("unexpected parsed shape"),
            }
        }
        (max_depth, max_bodies)
    }
    #[test]
    fn generated_sources_parse_with_bounded_shapes() {
        std::thread::Builder::new().stack_size(crate::STACK_8MIB).spawn(||{
            let set=corpus();let mut sources=0;let mut max_depth=0;let mut max_bodies=0;let mut max_bytes=0;
            for (i,rule) in set.rules.iter().enumerate() {
                for source in rule.tree.sources() {
                    let program=crate::Program::compile(&source).unwrap_or_else(|e|panic!("attempt {} family {} source {source}: {e:?}",rule.attempt,rule.metadata.family));
                    let (depth,bodies)=parsed_shape(program.expression());
                    assert!(depth<=rule.metadata.expanded_depth_bound,"attempt {} grammar bound {} actual {depth}: {source}",rule.attempt,rule.metadata.expanded_depth_bound);
                    assert!(depth<=32 && bodies<=2,"attempt {} depth={depth} bodies={bodies}: {source}",rule.attempt);
                    sources+=1;max_depth=max_depth.max(depth);max_bodies=max_bodies.max(bodies);max_bytes=max_bytes.max(source.len());
                }
                if i%1000==0 {println!("GENERATOR_PARSE_PROGRESS {i}/{}",set.rules.len());}
            }
            println!("GENERATOR_PARSE_SUMMARY rules={} sources={sources} max_depth={max_depth} max_bodies={max_bodies} max_source_bytes={max_bytes}",set.rules.len());
        }).unwrap().join().unwrap();
    }
}
