//! Native symbolic resource envelope. Runtime and estimator call the same rows.
//! Exit levels are retained separately from peaks; each loop resets temporary
//! memory, while retained map/filter results spend distinct-item sums.
use crate::charges::{self, Cost, Quantity};
use crate::common::ast::{
    operators as op, ComprehensionExpr, EntryExpr, Expr, IdedExpr, LiteralValue,
};
use crate::comprehension::{self, AppendStep, Macro};
use crate::quantity::{Quota, Sym};
use crate::regexes::PreparedRegex;
use crate::symbolic_control::{self as control, Resource};
use crate::{Declarations, InputKind, Policy, ScalarType};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bound {
    pub work: u64,
    pub memory: u64,
    pub retained: u64,
    pub result_nodes: u64,
    pub result_bytes: u64,
    pub result_depth: usize,
    pub resource_product: bool,
}
#[derive(Clone, Debug)]
pub(crate) struct Refusal {
    pub expr_id: u64,
    pub cap: &'static str,
    pub measured: u64,
    pub limit: u64,
}
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} exceeds {}; move repeated scans/copies to a SQL join or projection",
            self.cap, self.measured, self.limit
        )
    }
}
#[derive(Clone, Debug)]
enum Kind {
    Scalar,
    Union(Vec<Shape>),
    Bool,
    Number,
    String,
    Bytes,
    Temporal,
    Map {
        identity: u64,
        entries: Sym,
        payload: Sym,
        field: Arc<Shape>,
        key: Arc<Shape>,
        key_bytes: Sym,
    },
    List {
        len: Sym,
        scope: usize,
        item: Arc<Shape>,
    },
}
#[derive(Debug)]
struct Shape {
    kind: Kind,
    nodes: Sym,
    bytes: Sym,
    depth: usize,
    borrowed: bool,
    key_of: Option<u64>,
    key_scope_field: Option<usize>,
}
#[cfg(any(test, feature = "native-proof-tools"))]
pub(crate) fn native_layout() -> (usize, usize) {
    (std::mem::size_of::<Shape>(), std::mem::size_of::<Kind>())
}
impl Clone for Shape {
    fn clone(&self) -> Self {
        if !control::spend(Resource::Shapes, 1) {
            return Self::overflow();
        }
        Self {
            kind: self.kind.clone(),
            nodes: self.nodes.clone(),
            bytes: self.bytes.clone(),
            depth: self.depth,
            borrowed: self.borrowed,
            key_of: self.key_of,
            key_scope_field: self.key_scope_field,
        }
    }
}
impl Shape {
    fn overflow() -> Self {
        Self {
            kind: Kind::Number,
            nodes: Sym::c(u64::MAX),
            bytes: Sym::c(u64::MAX),
            depth: 1,
            borrowed: false,
            key_of: None,
            key_scope_field: None,
        }
    }
    fn share(shape: Self) -> Arc<Self> {
        if !control::spend(Resource::Shapes, 1) {
            static OVERFLOW: std::sync::OnceLock<Arc<Shape>> = std::sync::OnceLock::new();
            return OVERFLOW.get_or_init(|| Arc::new(Self::overflow())).clone();
        }
        Arc::new(shape)
    }
    fn scalar(kind: Kind, bytes: Sym) -> Self {
        if !control::spend(Resource::Shapes, 1) {
            return Self::overflow();
        }
        Self {
            kind,
            nodes: Sym::c(1),
            bytes,
            depth: 1,
            borrowed: false,
            key_of: None,
            key_scope_field: None,
        }
    }
    fn bool() -> Self {
        Self::scalar(Kind::Bool, Sym::c(8))
    }
    fn number() -> Self {
        Self::scalar(Kind::Number, Sym::c(8))
    }
    fn text(&self) -> Sym {
        match self.kind {
            Kind::Bool | Kind::Number | Kind::Temporal | Kind::Map { .. } | Kind::List { .. } => {
                Sym::c(0)
            }
            Kind::Union(ref variants) => variants.iter().fold(Sym::c(0), |n, s| n.max(&s.text())),
            _ => self.bytes.clone(),
        }
    }
    fn aggregate(&self) -> bool {
        match &self.kind {
            Kind::List { .. } | Kind::Map { .. } => true,
            Kind::Union(v) => v.iter().any(Self::aggregate),
            _ => false,
        }
    }
    fn rebind(&self, from: usize, to: usize) -> Self {
        if !control::spend(Resource::Shapes, 1) {
            return Self::scalar(Kind::Number, Sym::c(u64::MAX));
        }
        let mut s = self.clone();
        if s.key_scope_field == Some(from) {
            s.key_scope_field = Some(to);
        }
        s.nodes = s.nodes.rebind(from, to);
        s.bytes = s.bytes.rebind(from, to);
        s.kind = match &s.kind {
            Kind::Map {
                identity,
                entries,
                payload,
                field,
                key,
                key_bytes,
            } => Kind::Map {
                identity: *identity,
                entries: entries.rebind(from, to),
                payload: payload.rebind(from, to),
                field: Shape::share(field.rebind(from, to)),
                key: Shape::share(key.rebind(from, to)),
                key_bytes: key_bytes.rebind(from, to),
            },
            Kind::List { len, scope, item } => Kind::List {
                len: len.rebind(from, to),
                scope: *scope,
                item: Shape::share(item.rebind(from, to)),
            },
            Kind::Union(v) => Kind::Union(v.iter().map(|s| s.rebind(from, to)).collect()),
            k => k.clone(),
        };
        s
    }
    fn invalidate_key_pass(&mut self) {
        self.key_of = None;
        self.key_scope_field = None;
        if let Kind::Union(v) = &mut self.kind {
            for variant in v {
                variant.invalidate_key_pass();
            }
        }
    }
}
#[derive(Clone)]
struct Summary {
    work: Sym,
    peak: Sym,
    exit: Sym,
    shape: Shape,
}
impl Summary {
    fn node(shape: Shape) -> Self {
        let c = charges::node_visit();
        Self {
            work: Sym::c(c.work),
            peak: Sym::c(c.memory),
            exit: Sym::c(c.memory),
            shape,
        }
    }
    fn charge(&mut self, c: Cost<Sym>) {
        self.work = self.work.add(&c.work);
        self.exit = self.exit.add(&c.memory);
        self.peak = self.peak.max(&self.exit);
    }
    fn sequence(&mut self, b: &Self) {
        self.work = self.work.add(&b.work);
        self.peak = self.peak.max(&self.exit.add(&b.peak));
        self.exit = self.exit.add(&b.exit);
    }
    fn diagnostic(&mut self) {
        let d = charges::diagnostic();
        self.charge(Cost::new(Sym::c(d.work * 2), Sym::c(d.memory * 2)));
    }
}
struct Estimator<'a> {
    env: BTreeMap<String, Shape>,
    scope: usize,
    regexes: &'a HashMap<String, PreparedRegex>,
    policy: &'a Policy,
    regex_weight: u64,
}
impl<'a> Estimator<'a> {
    fn fresh(&mut self) -> usize {
        self.scope += 1;
        self.scope
    }
    fn join(&mut self, a: &Shape, b: &Shape) -> Shape {
        if !control::spend(Resource::Shapes, 1) {
            return Shape::scalar(Kind::Number, Sym::c(u64::MAX));
        }
        let mut s = a.clone();
        s.nodes = a.nodes.max(&b.nodes);
        s.bytes = a.bytes.max(&b.bytes);
        s.depth = a.depth.max(b.depth);
        s.borrowed = a.borrowed && b.borrowed;
        s.key_of = if a.key_of == b.key_of { a.key_of } else { None };
        s.key_scope_field = if a.key_scope_field == b.key_scope_field {
            a.key_scope_field
        } else {
            None
        };
        s.kind = match (&a.kind, &b.kind) {
            (
                Kind::List {
                    len: al,
                    scope: ascope,
                    item: ai,
                },
                Kind::List {
                    len: bl,
                    scope: bscope,
                    item: bi,
                },
            ) => {
                // Never rename a binder onto a scope already free in the other
                // alternative. Both alternatives enter a globally fresh scope.
                let scope = self.fresh();
                Kind::List {
                    len: al.max(bl),
                    scope,
                    item: Shape::share(
                        self.join(&ai.rebind(*ascope, scope), &bi.rebind(*bscope, scope)),
                    ),
                }
            }
            (
                Kind::Map {
                    identity,
                    entries: ae,
                    payload: ap,
                    field: af,
                    key: ak,
                    key_bytes: ab,
                },
                Kind::Map {
                    entries: be,
                    payload: bp,
                    field: bf,
                    key: bk,
                    key_bytes: bb,
                    ..
                },
            ) => Kind::Map {
                identity: *identity,
                entries: ae.max(be),
                payload: ap.max(bp),
                field: Shape::share(self.join(af, bf)),
                key: Shape::share(self.join(ak, bk)),
                key_bytes: ab.max(bb),
            },
            (Kind::String, Kind::String) => Kind::String,
            (Kind::Bytes, Kind::Bytes) => Kind::Bytes,
            (Kind::Bool, Kind::Bool) => Kind::Bool,
            (Kind::Number, Kind::Number) => Kind::Number,
            (Kind::Temporal, Kind::Temporal) => Kind::Temporal,
            (Kind::Scalar, Kind::Scalar) => Kind::Scalar,
            _ => {
                // Merge by runtime kind: at most the finite admitted kind set,
                // so conditional branches cannot create exponential products.
                let mut variants = Vec::<Shape>::new();
                for source in [a, b] {
                    let alternatives = match &source.kind {
                        Kind::Union(v) => v.clone(),
                        _ => vec![source.clone()],
                    };
                    for v in alternatives {
                        if let Some(old) = variants.iter_mut().find(|old| {
                            std::mem::discriminant(&old.kind) == std::mem::discriminant(&v.kind)
                        }) {
                            *old = self.join(old, &v);
                        } else {
                            variants.push(v);
                        }
                    }
                }
                Kind::Union(variants)
            }
        };
        s
    }
    fn row(&self, id: u64, e: Sym, p: Sym) -> Shape {
        let field = Shape::scalar(
            Kind::Scalar,
            Sym::c(8).max(&p.min_bound(&Sym::c(self.policy.string_bytes_candidate() as u64))),
        );
        Shape {
            kind: Kind::Map {
                identity: id,
                entries: e.clone(),
                payload: p.clone(),
                field: Shape::share(field),
                key: Shape::share(Shape::scalar(Kind::String, p.clone())),
                key_bytes: p.clone(),
            },
            nodes: Sym::c(1).add(&e),
            bytes: e.mul(&Sym::c(72)).add(&p),
            depth: 2,
            borrowed: true,
            key_of: None,
            key_scope_field: None,
        }
    }
    fn new(
        declarations: &Declarations,
        regexes: &'a HashMap<String, PreparedRegex>,
        policy: &'a Policy,
    ) -> Self {
        let mut this = Self {
            env: BTreeMap::new(),
            scope: 0,
            regexes,
            policy,
            regex_weight: 0,
        };
        for (i, (name, kind)) in declarations.entries.iter().enumerate() {
            let e = Sym::budget(Quota::Entries, i);
            let p = Sym::budget(Quota::Payload, i);
            let shape = match kind {
                InputKind::One => this.row(i as u64, e, p),
                InputKind::Many => {
                    let scope = this.fresh();
                    let n = Sym::input(crate::input::ROWS_PER_INPUT as u64, Some(i));
                    let row = this.row(
                        i as u64,
                        Sym::parameter(scope, e.clone(), e.clone()),
                        Sym::parameter(scope, p.clone(), p.clone()),
                    );
                    Shape {
                        kind: Kind::List {
                            len: n.clone(),
                            scope,
                            item: Shape::share(row),
                        },
                        nodes: Sym::c(1).add(&n).add(&e),
                        bytes: n.mul(&Sym::c(32)).add(&e.mul(&Sym::c(72))).add(&p),
                        depth: 3,
                        borrowed: true,
                        key_of: None,
                        key_scope_field: None,
                    }
                }
                InputKind::Scalar { kind, .. } => {
                    let mut scalar = match kind {
                        ScalarType::Int | ScalarType::Double => Shape::number(),
                        ScalarType::Bool => Shape::bool(),
                        ScalarType::String => Shape::scalar(
                            Kind::String,
                            p.min_bound(&Sym::c(policy.string_bytes_candidate() as u64)),
                        ),
                        ScalarType::Any => Shape::scalar(
                            Kind::Scalar,
                            Sym::c(8)
                                .max(&p.min_bound(&Sym::c(policy.string_bytes_candidate() as u64))),
                        ),
                    };
                    scalar.borrowed = true;
                    scalar
                }
            };
            this.env.insert(name.clone(), shape);
        }
        this
    }
    fn select_shape(&mut self, container: &Shape) -> Shape {
        match &container.kind {
            Kind::Map { field, .. } => field.as_ref().clone(),
            Kind::Union(variants) => {
                let mut selected = None;
                for variant in variants {
                    let field = self.select_shape(variant);
                    selected = Some(match selected {
                        Some(old) => self.join(&old, &field),
                        None => field,
                    });
                }
                selected.unwrap_or_else(Shape::number)
            }
            _ => Shape::number(), // typed semantic error: no successful field
        }
    }
    fn list(&mut self, elements: &[Shape]) -> Shape {
        let scope = self.fresh();
        let len = Sym::c(elements.len() as u64);
        let mut nodes = Sym::c(0);
        let mut bytes = Sym::c(0);
        let mut item = Shape::number();
        for (i, e) in elements.iter().enumerate() {
            nodes = nodes.add(&e.nodes);
            bytes = bytes.add(&e.bytes);
            item = if i == 0 {
                e.clone()
            } else {
                self.join(&item, e)
            };
        }
        if elements.len() > 1 {
            item.invalidate_key_pass();
        }
        item.nodes = Sym::parameter(scope, item.nodes.clone(), nodes.clone());
        item.bytes = Sym::parameter(scope, item.bytes.clone(), bytes.clone());
        Shape {
            kind: Kind::List {
                len: len.clone(),
                scope,
                item: Shape::share(item.clone()),
            },
            nodes: Sym::c(1).add(&nodes),
            bytes: len.mul(&Sym::c(32)).add(&bytes),
            depth: 1 + item.depth,
            borrowed: false,
            key_of: None,
            key_scope_field: None,
        }
    }
    fn expr(&mut self, e: &IdedExpr) -> Result<Summary, Refusal> {
        if let Some(r) = control::refusal() {
            return Err(Refusal {
                expr_id: e.id,
                cap: r.cap,
                measured: r.measured,
                limit: r.limit,
            });
        }
        let error = |cap| Refusal {
            expr_id: e.id,
            cap,
            measured: u64::MAX,
            limit: 0,
        };
        let mut s = Summary::node(Shape::number());
        match &e.expr {
            Expr::Literal(v) => {
                s.shape = match v {
                    LiteralValue::String(v) => {
                        Shape::scalar(Kind::String, Sym::c(v.inner().len() as u64))
                    }
                    LiteralValue::Bytes(v) => {
                        Shape::scalar(Kind::Bytes, Sym::c(v.inner().len() as u64))
                    }
                    LiteralValue::Boolean(_) => Shape::bool(),
                    _ => Shape::number(),
                };
                s.shape.borrowed = true;
                if matches!(v, LiteralValue::String(_) | LiteralValue::Bytes(_)) {
                    s.charge(charges::string_or_bytes_literal(s.shape.bytes.clone()));
                }
            }
            Expr::Ident(name) => {
                s.shape = self.env.get(name).cloned().unwrap_or_else(Shape::number);
                s.shape.borrowed = true;
            }
            Expr::Select(select) => {
                let a = self.expr(&select.operand)?;
                s.sequence(&a);
                s.charge(charges::payload_copy(
                    Sym::c(1),
                    Sym::c(select.field.len() as u64),
                ));
                s.charge(charges::map_key_lookup(Sym::c(select.field.len() as u64)));
                s.shape = if select.test {
                    Shape::bool()
                } else {
                    self.select_shape(&a.shape)
                };
                if !a.shape.borrowed && !select.test {
                    s.charge(charges::aggregate_select(
                        s.shape.nodes.clone(),
                        s.shape.bytes.clone(),
                    ));
                }
                s.shape.borrowed = a.shape.borrowed;
                s.diagnostic();
            }
            Expr::List(list) => {
                let mut shapes = vec![];
                let mut nodes = Sym::c(0);
                let mut bytes = Sym::c(0);
                for child in &list.elements {
                    let a = self.expr(child)?;
                    s.sequence(&a);
                    nodes = nodes.add(&a.shape.nodes);
                    bytes = bytes.add(&a.shape.bytes);
                    shapes.push(a.shape);
                }
                s.charge(charges::list_literal(
                    Sym::c(shapes.len() as u64),
                    nodes,
                    bytes.clone(),
                ));
                s.charge(charges::literal_text_payload(bytes));
                s.shape = self.list(&shapes);
            }
            Expr::Map(map) => {
                let mut nodes = Sym::c(1);
                let mut bytes = Sym::c(64 * map.entries.len() as u64);
                let mut payload = Sym::c(0);
                let mut field = Shape::number();
                let mut key_shape = Shape::number();
                let mut key_bytes = Sym::c(0);
                for (i, entry) in map.entries.iter().enumerate() {
                    let EntryExpr::MapEntry(entry) = &entry.expr else {
                        return Err(error("unsupported_ast"));
                    };
                    let k = self.expr(&entry.key)?;
                    s.sequence(&k);
                    s.charge(charges::payload_copy(
                        k.shape.nodes.clone(),
                        k.shape.bytes.clone(),
                    ));
                    key_shape = if i == 0 {
                        k.shape.clone()
                    } else {
                        self.join(&key_shape, &k.shape)
                    };
                    key_bytes = key_bytes.add(&k.shape.bytes);
                    let v = self.expr(&entry.value)?;
                    s.sequence(&v);
                    nodes = nodes.add(&v.shape.nodes);
                    bytes = bytes.add(&k.shape.bytes).add(&v.shape.bytes);
                    payload = payload.add(&k.shape.bytes).add(&v.shape.bytes);
                    field = if i == 0 {
                        v.shape
                    } else {
                        self.join(&field, &v.shape)
                    };
                }
                s.charge(charges::map_literal_rollup(
                    Sym::c(map.entries.len() as u64),
                    nodes.clone(),
                    bytes.clone(),
                ));
                s.charge(charges::literal_text_payload(payload.clone()));
                s.diagnostic();
                s.shape = Shape {
                    kind: Kind::Map {
                        identity: e.id + 1_000_000,
                        entries: Sym::c(map.entries.len() as u64),
                        payload,
                        field: Shape::share(field.clone()),
                        key: Shape::share(key_shape),
                        key_bytes,
                    },
                    nodes,
                    bytes,
                    depth: 1 + field.depth,
                    borrowed: false,
                    key_of: None,
                    key_scope_field: None,
                };
            }
            Expr::Call(call) => {
                let mut args = vec![];
                // Charging all operands is safe for conditional/boolean short circuit,
                // and composes semantic-error prefixes without a first-match discount.
                for a in call
                    .target
                    .iter()
                    .map(|x| x.as_ref())
                    .chain(call.args.iter())
                {
                    let a = self.expr(a)?;
                    s.sequence(&a);
                    args.push(a.shape);
                }
                let previous_weight = self.regex_weight;
                self.regex_weight = if call.func_name == "matches" {
                    let pattern = if call.target.is_some() {
                        call.args.first()
                    } else {
                        call.args.get(1)
                    };
                    match pattern.map(|p| &p.expr) {
                        Some(Expr::Literal(LiteralValue::String(p))) => {
                            self.regexes.get(p.inner()).map(|r| r.weight).unwrap_or(0)
                        }
                        _ => 0,
                    }
                } else {
                    0
                };
                let result = self.call(e.id, &call.func_name, &args, &mut s);
                self.regex_weight = previous_weight;
                result?;
            }
            Expr::Comprehension(c) => s = self.comprehension(e.id, c)?,
            _ => return Err(error("unsupported_ast")),
        }
        if s.shape.depth > crate::limits::VALUE_DEPTH {
            return Err(Refusal {
                expr_id: e.id,
                cap: "value_depth",
                measured: s.shape.depth as u64,
                limit: crate::limits::VALUE_DEPTH as u64,
            });
        };
        Ok(s)
    }
    fn call(
        &mut self,
        id: u64,
        name: &str,
        args: &[Shape],
        s: &mut Summary,
    ) -> Result<(), Refusal> {
        // Gate arity before union dispatch. Invalid variadic calls must not
        // form an exponential Cartesian product of conditional argument kinds.
        let valid_arity = match name {
            op::CONDITIONAL => args.len() == 3,
            op::NEGATE
            | op::LOGICAL_NOT
            | op::NOT_STRICTLY_FALSE
            | "size"
            | "min"
            | "max"
            | "string"
            | "bytes"
            | "int"
            | "uint"
            | "double"
            | "duration"
            | "timestamp"
            | "dyn" => args.len() == 1,
            "getFullYear" | "getMonth" | "getDayOfYear" | "getDayOfMonth" | "getDate"
            | "getDayOfWeek" | "getHours" | "getMinutes" | "getSeconds" | "getMilliseconds" => {
                matches!(args.len(), 1 | 2)
            }
            _ => args.len() == 2,
        };
        if !valid_arity {
            s.diagnostic();
            // Runtime's named precharge deliberately precedes overload matching.
            let a = args.first().cloned().unwrap_or_else(Shape::number);
            let b = args.get(1).cloned().unwrap_or_else(Shape::number);
            match name {
                "contains" if !args.is_empty() => {
                    s.charge(charges::containment_in_list(
                        a.nodes.clone(),
                        a.bytes.clone(),
                    ));
                    s.charge(charges::map_key_lookup(b.text()));
                    s.charge(charges::string_contains(a.text(), b.text()));
                }
                "startsWith" | "endsWith" if !args.is_empty() => {
                    s.charge(charges::string_contains(a.text(), b.text()))
                }
                _ => {}
            }
            s.shape = Shape::number();
            return Ok(());
        }
        if let Some((index, variants)) = args.iter().enumerate().find_map(|(i, a)| {
            if let Kind::Union(v) = &a.kind {
                Some((i, v.clone()))
            } else {
                None
            }
        }) {
            let mut merged: Option<Summary> = None;
            for variant in variants {
                let mut args = args.to_vec();
                args[index] = variant;
                let mut branch = Summary {
                    work: Sym::c(0),
                    peak: Sym::c(0),
                    exit: Sym::c(0),
                    shape: Shape::number(),
                };
                self.call(id, name, &args, &mut branch)?;
                if let Some(m) = &mut merged {
                    m.work = m.work.max(&branch.work);
                    m.peak = m.peak.max(&branch.peak);
                    m.exit = m.exit.max(&branch.exit);
                    m.shape = self.join(&m.shape, &branch.shape);
                } else {
                    merged = Some(branch);
                }
            }
            if let Some(m) = merged {
                s.sequence(&m);
                s.shape = m.shape;
            }
            return Ok(());
        }
        let a = args.first().cloned().unwrap_or_else(Shape::number);
        let b = args.get(1).cloned().unwrap_or_else(Shape::number);
        // All matching-name type errors remain runtime semantic errors. Bounds
        // include two bounded descriptors, fixed messages, and error prefixes.
        s.diagnostic();
        s.shape = match name {
            op::CONDITIONAL => args
                .get(1)
                .zip(args.get(2))
                .map(|(a, b)| self.join(a, b))
                .unwrap_or_else(Shape::number),
            op::LOGICAL_AND | op::LOGICAL_OR | op::LOGICAL_NOT | op::NOT_STRICTLY_FALSE => {
                Shape::bool()
            }
            op::EQUALS | op::NOT_EQUALS => {
                if a.aggregate() || b.aggregate() {
                    s.charge(charges::equality_aggregate(
                        a.nodes.clone(),
                        a.bytes.clone(),
                        b.nodes.clone(),
                        b.bytes.clone(),
                    ));
                } else {
                    s.charge(charges::equality_text(a.text(), b.text()));
                }
                Shape::bool()
            }
            op::LESS | op::LESS_EQUALS | op::GREATER | op::GREATER_EQUALS => {
                s.charge(charges::string_or_bytes_order(a.text(), b.text()));
                Shape::bool()
            }
            op::ADD => match (&a.kind, &b.kind) {
                (
                    Kind::List {
                        len: al,
                        scope: ascope,
                        item: ai,
                    },
                    Kind::List {
                        len: bl,
                        scope: bscope,
                        item: bi,
                    },
                ) => {
                    s.charge(charges::list_concat(
                        a.nodes.clone(),
                        a.bytes.clone(),
                        b.nodes.clone(),
                        b.bytes.clone(),
                    ));
                    let scope = self.fresh();
                    let len = al.add(bl);
                    let mut item =
                        self.join(&ai.rebind(*ascope, scope), &bi.rebind(*bscope, scope));
                    item.invalidate_key_pass();
                    item.nodes = Sym::parameter(
                        scope,
                        ai.nodes.maximum(*ascope).max(&bi.nodes.maximum(*bscope)),
                        ai.nodes.sum(*ascope, al).add(&bi.nodes.sum(*bscope, bl)),
                    );
                    item.bytes = Sym::parameter(
                        scope,
                        ai.bytes.maximum(*ascope).max(&bi.bytes.maximum(*bscope)),
                        ai.bytes.sum(*ascope, al).add(&bi.bytes.sum(*bscope, bl)),
                    );
                    Shape {
                        kind: Kind::List {
                            len,
                            scope,
                            item: Shape::share(item),
                        },
                        nodes: a.nodes.add(&b.nodes),
                        bytes: a.bytes.add(&b.bytes),
                        depth: a.depth.max(b.depth),
                        borrowed: false,
                        key_of: None,
                        key_scope_field: None,
                    }
                }
                (
                    Kind::String | Kind::Bytes | Kind::Scalar,
                    Kind::String | Kind::Bytes | Kind::Scalar,
                ) => {
                    s.charge(charges::string_concat(a.bytes.clone(), b.bytes.clone()));
                    Shape::scalar(
                        if matches!(a.kind, Kind::Bytes) {
                            Kind::Bytes
                        } else if matches!(a.kind, Kind::Scalar) {
                            Kind::Scalar
                        } else {
                            Kind::String
                        },
                        a.bytes.add(&b.bytes),
                    )
                }
                (Kind::Temporal, _) | (_, Kind::Temporal) => {
                    Shape::scalar(Kind::Temporal, Sym::c(8))
                }
                _ => Shape::number(),
            },
            op::SUBSTRACT | op::MULTIPLY | op::DIVIDE | op::MODULO | op::NEGATE => {
                if matches!(a.kind, Kind::Temporal) {
                    Shape::scalar(Kind::Temporal, Sym::c(8))
                } else {
                    Shape::number()
                }
            }
            op::IN => {
                match &b.kind {
                    Kind::List { .. } => s.charge(charges::containment_in_list(
                        b.nodes.clone(),
                        b.bytes.clone(),
                    )),
                    Kind::Map { .. } => s.charge(charges::map_key_lookup(a.text())),
                    _ => {}
                }
                Shape::bool()
            }
            op::INDEX => {
                let mut selected = match &a.kind {
                    Kind::List { item, .. } => item.as_ref().clone(),
                    Kind::Map {
                        identity,
                        field,
                        payload,
                        entries,
                        ..
                    } => {
                        let mut field = field.as_ref().clone();
                        // Key iteration selects distinct values once per key pass.
                        // Arbitrary repeated field/key projections cannot spend this total.
                        if b.key_of == Some(*identity) {
                            if let Some(scope) = b.key_scope() {
                                field.bytes = Sym::parameter(
                                    scope,
                                    field.bytes.clone(),
                                    payload.add(&entries.mul(&Sym::c(8))),
                                );
                                field.nodes = Sym::parameter(
                                    scope,
                                    field.nodes.clone(),
                                    a.nodes.clone().saturating_sub(1),
                                );
                            }
                        }
                        field
                    }
                    _ => Shape::number(),
                };
                if matches!(a.kind, Kind::Map { .. }) {
                    s.charge(charges::map_key_lookup(b.text()));
                }
                if !a.borrowed {
                    s.charge(charges::aggregate_select(
                        selected.nodes.clone(),
                        selected.bytes.clone(),
                    ));
                }
                selected.borrowed = a.borrowed;
                selected
            }
            "size" => {
                if matches!(a.kind, Kind::String | Kind::Scalar) {
                    s.charge(charges::size_string(a.text()));
                }
                Shape::number()
            }
            "contains" => {
                match &a.kind {
                    Kind::List { .. } => s.charge(charges::containment_in_list(
                        a.nodes.clone(),
                        a.bytes.clone(),
                    )),
                    Kind::Map { .. } => s.charge(charges::map_key_lookup(b.text())),
                    _ => s.charge(charges::string_contains(a.text(), b.text())),
                }
                Shape::bool()
            }
            "startsWith" | "endsWith" => {
                s.charge(charges::string_contains(a.text(), b.text()));
                Shape::bool()
            }
            "matches" => {
                let tier = self.regex_weight;
                s.charge(charges::regex_search(
                    a.text(),
                    Sym::c(tier),
                    self.policy.regex_k_re(),
                ));
                Shape::bool()
            }
            "min" | "max" => {
                if let Kind::List { len, .. } = &a.kind {
                    s.charge(charges::list_extremum(len.clone()));
                    let c = charges::extremum_result();
                    s.charge(Cost::new(Sym::c(c.work), Sym::c(c.memory)));
                }
                Shape::number()
            }
            "string" => {
                let out = match a.kind {
                    Kind::String => a.bytes.clone(),
                    Kind::Bytes => a.bytes.mul(&Sym::c(3)),
                    Kind::Scalar => a.bytes.max(&Sym::c(344)),
                    Kind::Temporal => Sym::c(40),
                    _ => Sym::c(344),
                };
                s.charge(charges::string_or_bytes_conversion(a.text(), out.clone()));
                Shape::scalar(Kind::String, out)
            }
            "bytes" => {
                s.charge(charges::string_or_bytes_conversion(
                    a.text(),
                    a.bytes.clone(),
                ));
                Shape::scalar(Kind::Bytes, a.bytes.clone())
            }
            "int" | "uint" | "double" | "duration" | "timestamp" => {
                s.charge(charges::string_parse(a.text()));
                Shape::scalar(
                    if name == "duration" || name == "timestamp" {
                        Kind::Temporal
                    } else {
                        Kind::Number
                    },
                    Sym::c(8),
                )
            }
            "dyn" => a,
            "getFullYear" | "getMonth" | "getDayOfYear" | "getDayOfMonth" | "getDate"
            | "getDayOfWeek" | "getHours" | "getMinutes" | "getSeconds" | "getMilliseconds" => {
                s.charge(charges::string_parse(b.text()));
                Shape::number()
            }
            _ => {
                return Err(Refusal {
                    expr_id: id,
                    cap: "unmodeled_function",
                    measured: 1,
                    limit: 0,
                })
            }
        };
        Ok(())
    }
    fn iterable(&mut self, shape: &Shape, scope: usize) -> (Sym, Shape) {
        match &shape.kind {
            Kind::List {
                len,
                scope: old,
                item,
            } => (len.clone(), item.rebind(*old, scope)),
            Kind::Map {
                identity,
                entries,
                key,
                key_bytes,
                ..
            } => {
                let mut key = key.as_ref().clone();
                key.bytes = Sym::parameter(scope, key.bytes.clone(), key_bytes.clone());
                key.key_of = Some(*identity);
                key.key_scope_set(scope);
                (entries.clone(), key)
            }
            Kind::Union(v) => {
                let mut result = None;
                for variant in v {
                    let (n, item) = self.iterable(variant, scope);
                    result = Some(match result {
                        None => (n, item),
                        Some((old_n, old_item)) => (n.max(&old_n), self.join(&old_item, &item)),
                    });
                }
                result.unwrap_or((Sym::c(0), Shape::number()))
            }
            _ => (Sym::c(0), Shape::number()),
        }
    }
    fn comprehension(&mut self, id: u64, c: &ComprehensionExpr) -> Result<Summary, Refusal> {
        let form = comprehension::classify(c).ok_or(Refusal {
            expr_id: id,
            cap: "raw_comprehension",
            measured: 1,
            limit: 0,
        })?;
        let mut s = Summary::node(Shape::number());
        let singleton = comprehension::singleton_range(c);
        let range = self.expr(singleton.unwrap_or(&c.iter_range))?;
        let scope = self.fresh();
        let (count, mut item) = if singleton.is_some() {
            (Sym::c(1), range.shape.clone())
        } else {
            self.iterable(&range.shape, scope)
        };
        item.borrowed = true;
        let previous = self.env.insert(c.iter_var.clone(), item.clone());
        let old_accu = self.env.insert(c.accu_var.clone(), Shape::number());
        let row = charges::comprehension_item_bind_ref();
        let bind = Cost::new(Sym::c(row.work), Sym::c(row.memory));
        let name = charges::payload_copy(Sym::c(1), Sym::c(c.iter_var.len() as u64));
        let mut iter = Summary {
            work: bind.work.add(&name.work),
            peak: bind.memory.add(&name.memory),
            exit: bind.memory.add(&name.memory),
            shape: Shape::number(),
        };
        match form {
            Macro::Fold(_, pred) => {
                s.sequence(&range);
                let body = self.expr(pred)?;
                iter.sequence(&body);
                s.work = s.work.add(&iter.work.sum(scope, &count));
                // One remembered semantic error can overlap the next iteration.
                s.peak = s.peak.max(
                    &s.exit
                        .add(&iter.peak.maximum(scope))
                        .add(&Sym::c(charges::RETAINED_ERROR_BYTES)),
                );
                s.exit = s.exit.add(&Sym::c(charges::RETAINED_ERROR_BYTES));
                s.shape = Shape::bool();
            }
            Macro::Append(step) => {
                let init = self.expr(&c.accu_init)?;
                s.sequence(&init);
                s.sequence(&range);
                s.charge(charges::payload_copy(
                    init.shape.nodes.clone(),
                    init.shape.bytes.clone(),
                ));
                let (predicate, element) = match step {
                    AppendStep::Map(e) => (None, e),
                    AppendStep::Filter { condition, element } => (Some(condition), element),
                };
                iter.charge(Cost::new(Sym::c(1), Sym::c(8))); // actual loop_cond visit
                if let Some(p) = predicate {
                    let p = self.expr(p)?;
                    iter.sequence(&p);
                }
                let body = self.expr(element)?;
                iter.sequence(&body);
                iter.charge(charges::list_append_in_place(
                    body.shape.nodes.clone(),
                    body.shape.bytes.clone(),
                ));
                let retained = count
                    .mul(&Sym::c(32))
                    .add(&body.shape.bytes.sum(scope, &count));
                s.work = s.work.add(&iter.work.sum(scope, &count));
                s.peak = s
                    .peak
                    .max(&s.exit.add(&retained).add(&iter.peak.maximum(scope)));
                s.exit = s.exit.add(&retained);
                s.shape = Shape {
                    kind: Kind::List {
                        len: count.clone(),
                        scope,
                        item: Shape::share(body.shape.clone()),
                    },
                    nodes: Sym::c(1).add(&body.shape.nodes.sum(scope, &count)),
                    bytes: retained,
                    depth: 1 + body.shape.depth,
                    borrowed: false,
                    key_of: None,
                    key_scope_field: None,
                };
            }
            Macro::ExistsOne(_) => {
                let init = self.expr(&c.accu_init)?;
                s.sequence(&init);
                s.sequence(&range);
                s.charge(charges::payload_copy(
                    init.shape.nodes.clone(),
                    init.shape.bytes.clone(),
                ));
                let condition = self.expr(&c.loop_cond)?;
                iter.sequence(&condition);
                let step = self.expr(&c.loop_step)?;
                iter.sequence(&step);
                iter.charge(charges::payload_copy(
                    step.shape.nodes.clone(),
                    step.shape.bytes.clone(),
                ));
                s.work = s.work.add(&iter.work.sum(scope, &count));
                s.peak = s.peak.max(&s.exit.add(&iter.peak.maximum(scope)));
                s.exit = s.exit.add(&Sym::c(8));
                let result = self.expr(&c.result)?;
                s.sequence(&result);
                s.charge(charges::payload_copy(
                    result.shape.nodes.clone(),
                    result.shape.bytes.clone(),
                ));
                s.shape = Shape::bool();
            }
        }
        if let Some(v) = previous {
            self.env.insert(c.iter_var.clone(), v);
        } else {
            self.env.remove(&c.iter_var);
        }
        if let Some(v) = old_accu {
            self.env.insert(c.accu_var.clone(), v);
        } else {
            self.env.remove(&c.accu_var);
        }
        Ok(s)
    }
}
// Key scope is explicit provenance rather than inferred from an observed key.
impl Shape {
    fn key_scope(&self) -> Option<usize> {
        self.key_scope_field
    }
    fn key_scope_set(&mut self, id: usize) {
        self.key_scope_field = Some(id);
    }
}
/// Public admission checks resource products first, independent of ceilings.
pub(crate) fn admit(bound: Bound, budget: crate::meter::Budget) -> Result<(), String> {
    if bound.resource_product {
        return Err(format!("cross_product: resource multiplication 1 exceeds permitted 0 (work bound {}, memory bound {}); move repeated input traversal/copy to a SQL join or projection", bound.work, bound.memory));
    }
    if bound.work > budget.work {
        return Err(format!(
            "work_cost: {} exceeds {}; move repeated scans/copies to a SQL join or projection",
            bound.work, budget.work
        ));
    }
    if bound.memory > budget.memory {
        return Err(format!(
            "memory_cost: {} exceeds {}; project or aggregate inputs in SQL",
            bound.memory, budget.memory
        ));
    }
    Ok(())
}
pub(crate) fn estimate(
    expr: &IdedExpr,
    declarations: &Declarations,
    regexes: &HashMap<String, PreparedRegex>,
    policy: &Policy,
) -> Result<(Bound, control::Counts), Refusal> {
    let (result, counts, refusal) =
        control::account(|| estimate_inner(expr, declarations, regexes, policy));
    if let Some(r) = refusal {
        return Err(Refusal {
            expr_id: expr.id,
            cap: r.cap,
            measured: r.measured,
            limit: r.limit,
        });
    }
    result.map(|bound| (bound, counts))
}
fn estimate_inner(
    expr: &IdedExpr,
    declarations: &Declarations,
    regexes: &HashMap<String, PreparedRegex>,
    policy: &Policy,
) -> Result<Bound, Refusal> {
    let mut s = Estimator::new(declarations, regexes, policy).expr(expr)?;
    s.charge(charges::result_emission(
        s.shape.nodes.clone(),
        s.shape.bytes.clone(),
    ));
    let value = |v: &Sym| {
        v.value().map_err(|_| Refusal {
            expr_id: expr.id,
            cap: "symbolic_overflow",
            measured: u64::MAX,
            limit: u64::MAX - 1,
        })
    };
    let bound = Bound {
        work: value(&s.work)?,
        memory: value(&s.peak)?,
        retained: value(&s.exit)?,
        result_nodes: value(&s.shape.nodes)?,
        result_bytes: value(&s.shape.bytes)?,
        result_depth: s.shape.depth,
        resource_product: s.work.cross_product() || s.shape.bytes.cross_product(),
    };
    Ok(bound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{api, evaluate, Bindings, InputDecl, Value};
    fn declarations() -> Declarations {
        Declarations::new(
            [
                InputDecl {
                    name: "rows".into(),
                    kind: InputKind::Many,
                },
                InputDecl {
                    name: "ys".into(),
                    kind: InputKind::Many,
                },
                InputDecl {
                    name: "one".into(),
                    kind: InputKind::One,
                },
                InputDecl {
                    name: "arg".into(),
                    kind: InputKind::Scalar {
                        kind: ScalarType::Any,
                        nullable: true,
                    },
                },
            ],
            &Policy::P0_INTERIM,
        )
        .unwrap()
    }
    fn row(i: i64) -> Value {
        Value::from(indexmap::IndexMap::from([
            ("id".to_string(), Value::Int(i)),
            (
                "body".to_string(),
                Value::String(Arc::new("x".repeat(i as usize + 1))),
            ),
            ("ok".to_string(), Value::Bool(i % 2 == 0)),
        ]))
    }
    #[test]
    fn borrowed_macro_ranges_keep_outputs_errors_and_lexical_scopes_bounded() {
        let p = Policy::MEASUREMENT_CANDIDATES[1];
        let d = Declarations::new(
            [
                InputDecl {
                    name: "one".into(),
                    kind: InputKind::One,
                },
                InputDecl {
                    name: "rows".into(),
                    kind: InputKind::Many,
                },
            ],
            &p,
        )
        .unwrap();
        let mut b = Bindings::empty(&d, &p);
        b.insert("one", &row(1)).unwrap();
        b.insert("rows", &Value::from(vec![row(0), row(1), row(2)]))
            .unwrap();
        for source in [
            "rows.map(r,r)",
            "rows.filter(r,true)",
            "rows.map(r,[r,r])",
            "rows.map(r,string(r.id)).map(r,r+'x')",
            "[one].map(q,[q].map(q,q.id))",
            "[[one]].map(r,r.map(q,q.id))",
            "[one].map(one,[one.id].map(one,string(one)+'x'))",
            "[{'n':one.id}].map(r,r.n)",
            "[one,one].all(q,size(q)>0)",
            "[one].all(q,q.missing>0)",
            "[0,1].all(q,q==0?1/0:false)",
            "[0,1].exists(q,q==0?1/0:true)",
            "[1,0].all(q,q==1?false:1/0)",
        ] {
            let prepared = api::check(source, &d, &p)
                .result
                .unwrap_or_else(|e| panic!("{source}: {e}"));
            let r = evaluate(&prepared, &b, &p);
            assert!(
                r.cost.work <= prepared.bound().work && r.cost.memory <= prepared.bound().memory,
                "{source}: {:?} {:?}",
                r.cost,
                prepared.bound()
            );
            if let Ok(v) = r.result {
                let (n, bytes) = crate::load::metrics(&v);
                assert!(
                    n <= prepared.bound().result_nodes && bytes <= prepared.bound().result_bytes
                );
            } else {
                assert_eq!(source, "[one].all(q,q.missing>0)");
            }
        }
        for source in [
            "rows.all(r,rows.all(q,true))",
            "rows.all(r,r in rows)",
            "rows.map(r,rows)",
        ] {
            assert!(
                api::check(source, &d, &p)
                    .result
                    .unwrap_err()
                    .to_string()
                    .contains("cross_product"),
                "{source}"
            );
        }
    }
    #[test]
    fn generic_one_singleton_read_in_many_loop_has_no_repeated_copy_bound() {
        let p = Policy::MEASUREMENT_CANDIDATES[1];
        let d = declarations();
        let source = "rows.map(r,[one].all(q,size(q)==10000))";
        let prepared = api::check(source, &d, &p).result.unwrap();
        assert!(!prepared.bound().resource_product);
        assert!(prepared.bound().work < 1_000_000 && prepared.bound().memory < 1_000_000);
        let mut b = Bindings::empty(&d, &p);
        b.insert(
            "rows",
            &Value::from(vec![
                Value::from(indexmap::IndexMap::<String, Value>::new());
                5000
            ]),
        )
        .unwrap();
        b.insert(
            "one",
            &Value::from(
                (0..10000)
                    .map(|i| (format!("k{i}"), Value::Int(0)))
                    .collect::<indexmap::IndexMap<_, _>>(),
            ),
        )
        .unwrap();
        b.insert("ys", &Value::from(Vec::<Value>::new())).unwrap();
        b.insert("arg", &Value::Int(0)).unwrap();
        let report = evaluate(&prepared, &b, &p);
        assert!(report.result.is_ok(), "{:?}", report.result);
        assert!(
            report.cost.work <= prepared.bound().work
                && report.cost.memory <= prepared.bound().memory
        );
    }
    #[test]
    fn admitted_estimates_report_bounded_native_auxiliary_control() {
        let d = declarations();
        for source in [
            "rows.map(r,[r,r,r])",
            "[one].map(m,(m.map(k,k)+m.map(k,k)).map(k,m[k]))",
            "(true?one:0).body",
            "rows.all(r,r.id in ys.map(t,t.id))",
        ] {
            let p = api::measure(source, &d, &Policy::P0_INTERIM)
                .result
                .unwrap();
            let counts = p.native_aux();
            assert!(counts.nodes > 0 && counts.nodes <= 250_000);
            assert!(counts.visits > 0 && counts.visits <= 1_000_000);
            assert!(counts.cells > 0 && counts.cells <= 1_000_000);
            assert!(counts.shapes > 0 && counts.shapes <= 16_384);
        }
    }
    #[test]
    fn estimator_covers_declared_native_expression_and_error_prefixes() {
        let d = declarations();
        let mut b = Bindings::empty(&d, &Policy::P0_INTERIM);
        b.insert("rows", &Value::from(vec![row(0), row(1), row(2)]))
            .unwrap();
        b.insert("ys", &Value::from(vec![row(1), row(2)])).unwrap();
        b.insert("one", &row(1)).unwrap();
        b.insert("arg", &Value::Int(-1)).unwrap();
        for source in [
            "1",
            "[1,2,3]",
            "{'a':'payload','b':one.body}",
            "rows",
            "one",
            "arg",
            "rows+ys",
            "(true?rows:'s')+rows",
            "(true?rows:'s').contains(rows[0])",
            "(true?rows:one).map(r,r)",
            "rows.all(r,r.id>=0)",
            "rows.exists(r,r.ok)",
            "rows.exists_one(r,r.ok)",
            "rows.map(r,r)",
            "rows.map(r,[r,r])",
            "rows.map(r,r.body)",
            "rows.filter(r,r.ok)",
            "rows.map(r,r.ok,r.body)",
            "rows.map(r,r.id).min()",
            "max(rows.map(r,double(r.id)))",
            "min(rows.map(r,uint(r.id)))",
            "min([])",
            "min([1,2.0])",
            "min([double('NaN'),double('NaN')])",
            "rows.map(r,r.body+string(r.id))",
            "rows.map(r,bytes(r.body))",
            "rows.map(r,string(bytes(r.body)))",
            "rows.map(r, r.body.contains('x'))",
            "rows.all(r,r.id in ys.map(t,t.id))",
            "rows.all(r,r in ys)",
            "rows.map(r, rows)",
            "rows.all(r,r.all(k,r[k]==r[k]))",
            "one == {'a':0,'b':0}",
            "rows[0].body",
            "rows.map(r,r)[0]",
            "rows.map(r,0)[0]",
            "rows[true]",
            "rows[0.5]",
            "{rows:0}",
            "rows in {}",
            "{}[rows]",
            "uint(arg)",
            "string(duration('1e99h1e99h1e99h'))",
            "timestamp('9999-12-31T23:59:59Z')+duration('1s')",
            "string(double('1e-323'))",
            "duration('1e20h').getSeconds()",
            "timestamp('2000-01-01T00:00:00Z').getDayOfYear()",
            "true?rows.map(r,r):ys.filter(r,true)",
            "one.body.matches('^x+$')",
            "[one].map(r,r.body)",
        ] {
            let p = api::measure(source, &d, &Policy::P0_INTERIM)
                .result
                .unwrap_or_else(|e| panic!("{source}: {e}"));
            let report = evaluate(&p, &b, &Policy::P0_INTERIM);
            let bound = p.bound();
            assert!(
                report.cost.work <= bound.work,
                "{source}: work {} > {}; {:?}",
                report.cost.work,
                bound.work,
                report.result
            );
            assert!(
                report.cost.memory <= bound.memory,
                "{source}: memory {} > {}; {:?}",
                report.cost.memory,
                bound.memory,
                report.result
            );
            if let Ok(v) = report.result {
                let (n, bytes) = crate::load::metrics(&v);
                assert!(
                    n <= bound.result_nodes && bytes <= bound.result_bytes,
                    "{source}: output {n}/{bytes} > {}/{}",
                    bound.result_nodes,
                    bound.result_bytes
                );
            }
        }
    }
    #[test]
    fn detector_covers_self_products_implicit_scans_and_derived_lists() {
        let d = declarations();
        for source in [
            "rows.all(r,r in ys)",
            "rows.all(r,r.id in ys.map(t,t.id))",
            "rows.map(r,rows)",
            "rows.all(r,r in rows)",
            "rows.all(r,r in (true?ys:rows))",
            "rows.all(r,r in (ys+rows))",
            "rows.all(r,r in ys.filter(t,true))",
        ] {
            assert!(
                api::measure(source, &d, &Policy::P0_INTERIM)
                    .result
                    .unwrap()
                    .bound()
                    .resource_product,
                "{source}"
            );
        }
        for source in [
            "rows.all(r,size(ys)>0)",
            "rows.map(r,[r,r])",
            "rows.all(r,r.all(k,r[k]==r[k]))",
        ] {
            assert!(
                !api::measure(source, &d, &Policy::P0_INTERIM)
                    .result
                    .unwrap()
                    .bound()
                    .resource_product,
                "{source}"
            );
        }
    }
}

#[cfg(test)]
mod aggregate_tests {
    use super::*;
    use crate::{api, evaluate, Bindings, InputDecl, Value};
    #[test]
    fn heterogeneous_rows_amortize_each_pass_and_price_repeated_results() {
        let d = Declarations::new(
            [InputDecl {
                name: "rows".into(),
                kind: InputKind::Many,
            }],
            &Policy::P0_INTERIM,
        )
        .unwrap();
        let big = Value::from(
            (0..10000)
                .map(|i| (format!("f{i}"), Value::Int(0)))
                .collect::<indexmap::IndexMap<_, _>>(),
        );
        let mut rows = vec![big];
        rows.extend((1..5000).map(|_| Value::from(indexmap::IndexMap::<String, Value>::new())));
        let value = Value::from(rows);
        let mut b = Bindings::empty(&d, &Policy::P0_INTERIM);
        b.insert("rows", &value).unwrap();
        let validated =
            crate::input::validate(&b.variables, &d, &Policy::P0_INTERIM, true).unwrap();
        assert_eq!(validated, 113899);
        assert_eq!(crate::load::metrics(&value), (15001, 928890));
        let mut previous = 0;
        for source in ["rows.map(r,r)", "rows.map(r,[r,r])", "rows.map(r,[r,r,r])"] {
            let p = api::measure(source, &d, &Policy::P0_INTERIM)
                .result
                .unwrap();
            let estimate = p.bound();
            assert!(estimate.work < 5_000_000, "{source}: {estimate:?}");
            assert!(
                estimate.result_bytes > previous,
                "{source}: repeated retention must grow"
            );
            previous = estimate.result_bytes;
            let report = evaluate(&p, &b, &Policy::P0_INTERIM);
            assert!(report.result.is_ok(), "{source}: {:?}", report.result);
            assert!(
                report.cost.work <= estimate.work && report.cost.memory <= estimate.memory,
                "{source}: {:?} {estimate:?}",
                report.cost
            );
        }
    }
}

#[cfg(test)]
mod key_shape_tests {
    use super::*;
    use crate::{api, evaluate, Bindings, InputDecl, Value};
    #[test]
    fn map_literal_key_kinds_preserve_conversion_output_and_error_bounds() {
        let d = Declarations::empty();
        let b = Bindings::empty(&d, &Policy::P0_INTERIM);
        for source in [
            "{9223372036854775807:''}.map(k,string(k))",
            "{18446744073709551615u:''}.map(k,string(k))",
            "{true:''}.map(k,k)",
            "{1:'',2u:'','text':'',false:''}.map(k,k)",
            "{1:'',2u:'','text':''}.map(k,bytes(string(k)))",
            "{true:''}.map(k,string(k))",
            "{true:''}.map(k,bytes(k))",
            "{1:''}.map(k,size(k))",
            "{1:''}.map(k,k.size())",
            "{1:'',2u:'','text':''}.map(k,string(k).size())",
        ] {
            let p = api::measure(source, &d, &Policy::P0_INTERIM)
                .result
                .unwrap();
            let r = evaluate(&p, &b, &Policy::P0_INTERIM);
            let bound = p.bound();
            assert!(
                r.cost.work <= bound.work && r.cost.memory <= bound.memory,
                "{source}: {:?} {bound:?}",
                r.cost
            );
            if let Ok(v) = r.result {
                let (n, bytes) = crate::load::metrics(&v);
                assert!(
                    n <= bound.result_nodes && bytes <= bound.result_bytes,
                    "{source}: {n}/{bytes} > {bound:?}"
                );
            }
        }
    }
    #[test]
    fn conditional_union_select_preserves_payload_copy_and_downstream_bounds() {
        let d = Declarations::new(
            [InputDecl {
                name: "one".into(),
                kind: InputKind::One,
            }],
            &Policy::P0_INTERIM,
        )
        .unwrap();
        let mut b = Bindings::empty(&d, &Policy::P0_INTERIM);
        b.insert(
            "one",
            &Value::from(indexmap::IndexMap::from([(
                "body".to_string(),
                Value::from("x".repeat(65_536)),
            )])),
        )
        .unwrap();
        for source in [
            "(true?one:0).body",
            "(false?0:one).body",
            "(false?one:0).body",
            "(true?0:one).body",
            "(true?(false?0:one):duration('0s')).body",
            "string((true?one:0).body)",
            "bytes((false?0:one).body)",
            "(true?one:0).body+(false?0:one).body",
            "[(true?one:0).body].map(x,string(x))",
            "[{'body':(true?one:0).body}].map(r,r.body)",
            "(true?{'body':one.body}:0).body",
            "size((true?one:0).body)",
        ] {
            // These foundation domain bounds use interim S=1MiB; cases above
            // P0 numeric ceilings are private measurement, not public admissions.
            let p = api::measure(source, &d, &Policy::P0_INTERIM)
                .result
                .unwrap();
            let r = evaluate(&p, &b, &Policy::P0_INTERIM);
            assert!(
                r.cost.work <= p.bound().work && r.cost.memory <= p.bound().memory,
                "{source}: {:?} {:?}",
                r.cost,
                p.bound()
            );
            if let Ok(v) = r.result {
                let (nodes, bytes) = crate::load::metrics(&v);
                assert!(
                    nodes <= p.bound().result_nodes && bytes <= p.bound().result_bytes,
                    "{source}: {nodes}/{bytes} > {:?}",
                    p.bound()
                );
            }
        }
        let p = api::check("(true?one:0).body", &d, &Policy::P0_INTERIM)
            .result
            .unwrap();
        let r = evaluate(&p, &b, &Policy::P0_INTERIM);
        assert_eq!(crate::load::metrics(&r.result.unwrap()), (1, 65_536));
        assert!(p.bound().result_bytes >= 65_536);
    }
    #[test]
    fn invalid_variadic_union_overloads_do_not_expand_cartesian_arguments() {
        let d = Declarations::empty();
        let b = Bindings::empty(&d, &Policy::P0_INTERIM);
        let args = vec!["(true ? 1 : '')"; 64].join(",");
        for source in [
            format!("string({args})"),
            format!("'x'.contains({args})"),
            format!("[1].contains({args})"),
            format!("'x'.startsWith({args})"),
        ] {
            let p = api::measure(&source, &d, &Policy::P0_INTERIM)
                .result
                .unwrap();
            let report = evaluate(&p, &b, &Policy::P0_INTERIM);
            assert!(matches!(
                report.result,
                Err(crate::ExecutionError::NoSuchOverload)
            ));
            assert!(
                report.cost.work <= p.bound().work && report.cost.memory <= p.bound().memory,
                "{source}: {:?} {:?}",
                report.cost,
                p.bound()
            );
        }
    }
    #[test]
    fn joined_list_binders_are_fresh_and_do_not_capture_other_free_scopes() {
        let regexes = HashMap::new();
        let mut est = Estimator::new(&Declarations::empty(), &regexes, &Policy::P0_INTERIM);
        // This models list A's binder O and list B's binder I with a free O
        // dependency. Merging must rename both binders to a fresh F, never I->O.
        let outer = est.fresh();
        let inner = est.fresh();
        let p = Sym::parameter(outer, Sym::c(10), Sym::c(10));
        let make_list = |scope, bytes: Sym| Shape {
            kind: Kind::List {
                len: Sym::c(1),
                scope,
                item: Shape::share(Shape::scalar(Kind::String, bytes)),
            },
            nodes: Sym::c(2),
            bytes: Sym::c(42),
            depth: 2,
            borrowed: false,
            key_of: None,
            key_scope_field: None,
        };
        let a = make_list(outer, Sym::parameter(outer, Sym::c(1), Sym::c(1)));
        let b = make_list(inner, Sym::parameter(inner, Sym::c(10), p));
        let joined = est.join(&a, &b);
        let Kind::List { scope, item, .. } = joined.kind else {
            unreachable!()
        };
        assert_ne!(scope, outer);
        assert_ne!(scope, inner);
        assert!(
            item.bytes
                .maximum(outer)
                .sum(outer, &Sym::c(2))
                .value()
                .unwrap()
                >= 20
        );
        assert!(
            item.bytes
                .sum(scope, &Sym::c(1))
                .sum(outer, &Sym::c(2))
                .value()
                .unwrap()
                >= 10
        );
    }
    #[test]
    fn invalid_list_add_kinds_use_only_bounded_error_prefixes() {
        let d = Declarations::new(
            [
                InputDecl {
                    name: "one".into(),
                    kind: InputKind::One,
                },
                InputDecl {
                    name: "rows".into(),
                    kind: InputKind::Many,
                },
            ],
            &Policy::P0_INTERIM,
        )
        .unwrap();
        let one = Value::from(indexmap::IndexMap::from([
            ("x".repeat(4096), Value::Int(0)),
            ("y".into(), Value::Int(0)),
        ]));
        let mut b = Bindings::empty(&d, &Policy::P0_INTERIM);
        b.insert("one", &one).unwrap();
        b.insert("rows", &Value::from(vec![one.clone(); 3]))
            .unwrap();
        for source in [
            "[] + one",
            "rows + one",
            "[] + {'a':''}",
            "[] + (true ? one : [])",
            "[] + (false ? [] : one)",
            "(true ? [] : one) + one",
            "[] + true",
            "[] + 'text'",
            "[] + 1",
            "[] + bytes('text')",
            "one + []",
        ] {
            let p = api::measure(source, &d, &Policy::P0_INTERIM)
                .result
                .unwrap();
            let r = evaluate(&p, &b, &Policy::P0_INTERIM);
            assert!(
                matches!(r.result, Err(crate::ExecutionError::NoSuchOverload))
                    || (source == "one + []"
                        && matches!(
                            r.result,
                            Err(crate::ExecutionError::UnsupportedBinaryOperator(..))
                        )),
                "{source}: {:?}",
                r.result
            );
            assert!(
                r.cost.work <= p.bound().work && r.cost.memory <= p.bound().memory,
                "{source}: {:?} {:?}",
                r.cost,
                p.bound()
            );
        }
        // Direct borrowed kind refusal neither charges concat nor enters its body.
        use crate::common::traits::Adder;
        let lhs = crate::common::types::list::DefaultList::from(Vec::<
            Box<dyn crate::common::value::Val>,
        >::new());
        let rhs = crate::common::types::map::DefaultMap::default();
        crate::meter::reset_body_runs();
        let (result, cost) =
            crate::load::account(Policy::P0_INTERIM.to_budget(), || lhs.add(&rhs).map(|_| ()));
        assert!(matches!(result, Err(crate::ExecutionError::NoSuchOverload)));
        assert_eq!(cost.work, 0);
        assert_eq!(cost.memory, 0);
        assert_eq!(crate::meter::op_bodies(), 0);
    }
    #[test]
    fn duplicated_key_materialization_does_not_reuse_one_injective_pass() {
        let d = Declarations::new(
            [InputDecl {
                name: "one".into(),
                kind: InputKind::One,
            }],
            &Policy::P0_INTERIM,
        )
        .unwrap();
        let mut b = Bindings::empty(&d, &Policy::P0_INTERIM);
        b.insert(
            "one",
            &Value::from(indexmap::IndexMap::from([(
                "body".to_string(),
                Value::String(Arc::new("x".repeat(4096))),
            )])),
        )
        .unwrap();
        for source in [
            "[{'a':one.body}].map(m,(m.map(k,k)+m.map(k,k)).map(k,m[k]))",
            "[{'a':one.body}].map(m,m.map(k,[k,k]).map(ks,ks.map(k,m[k])))",
            "[{'a':one.body}].map(m,(true?m.map(k,k)+m.map(k,k):m.map(k,k)).map(k,m[k]))",
            "[{'a':one.body}].map(m,m.filter(k,true).map(k,m[k]))",
        ] {
            let p = match api::measure(source, &d, &Policy::P0_INTERIM).result {
                Ok(p) => p,
                Err(e) => {
                    // The literal-key duplication source genuinely has three BODY
                    // levels; it is an L1 refusal rather than an admission witness.
                    assert!(
                        e.to_string().contains("comprehension_depth"),
                        "{source}: {e}"
                    );
                    continue;
                }
            };
            let r = evaluate(&p, &b, &Policy::P0_INTERIM);
            let v = r.result.unwrap();
            let (n, bytes) = crate::load::metrics(&v);
            let bound = p.bound();
            assert!(
                n <= bound.result_nodes && bytes <= bound.result_bytes,
                "{source}: {n}/{bytes} > {bound:?}"
            );
            assert!(r.cost.work <= bound.work && r.cost.memory <= bound.memory);
        }
        // [k,k] copies the selected result twice within a distinct key pass.
        let source = "[{'a':one.body}].map(m,m.map(k,[m[k],m[k]]))";
        let p = api::measure(source, &d, &Policy::P0_INTERIM)
            .result
            .unwrap();
        let r = evaluate(&p, &b, &Policy::P0_INTERIM);
        let (n, bytes) = crate::load::metrics(&r.result.unwrap());
        assert!(n <= p.bound().result_nodes && bytes <= p.bound().result_bytes);
        assert!(r.cost.work <= p.bound().work && r.cost.memory <= p.bound().memory);
    }
}
