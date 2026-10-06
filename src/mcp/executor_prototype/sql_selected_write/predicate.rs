//! Closed SELECT grammar. SQL is parsed, never dispatched to a database.
use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use turso_parser::{ast::*, lexer::Lexer, parser::Parser, token::TokenType};

use crate::error::{Error, Result};

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "lowercase")]
pub(super) enum Scalar {
    Null,
    Text(String),
    Boolean(bool),
}

#[derive(Clone, Debug, Serialize)]
pub(super) enum Field {
    Raw(String),
    Facet(String),
}
impl Field {
    fn boolean(&self) -> bool {
        matches!(self, Self::Raw(s) if s == "archived")
    }
}

#[derive(Debug, Serialize)]
pub(super) enum Predicate {
    All,
    Compare(Field, Scalar, bool),
    In(Field, Vec<Scalar>, bool),
    Null(Field, bool),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Not(Box<Self>),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Truth {
    True,
    False,
    Unknown,
}
impl Truth {
    fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => self,
        }
    }
    fn and(self, rhs: Self) -> Self {
        match (self, rhs) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::True, Self::True) => Self::True,
            _ => Self::Unknown,
        }
    }
    fn or(self, rhs: Self) -> Self {
        match (self, rhs) {
            (Self::True, _) | (_, Self::True) => Self::True,
            (Self::False, Self::False) => Self::False,
            _ => Self::Unknown,
        }
    }
}

pub(super) struct Program {
    pub predicate: Predicate,
    pub keys: BTreeSet<String>,
    pub parameter_contexts: BTreeMap<usize, bool>,
}

fn refuse(message: &str) -> Error {
    Error::conflict(format!(
        "sql_write: {message}; use SELECT id FROM children with supported typed predicates"
    ))
}

// Iterate the parser's lexer BEFORE recursive parser entry. The closed alphabet
// excludes all recursive query/CASE/function forms except one literal accessor.
// Parentheses and NOT are separately bounded; the locked parser also has its
// own expression height/recursion guard. Comments/strings are indivisible tokens.
fn preflight(sql: &str) -> Result<()> {
    if sql.is_empty() || sql.len() > 65_536 || sql.contains('\0') {
        return Err(refuse(
            "statement byte bound exceeded or empty/NUL statement",
        ));
    }
    let mut depth = 0usize;
    let mut count = 0;
    let mut nots = 0;
    let mut selects = 0;
    let mut froms = 0;
    let mut wheres = 0;
    let mut ended = false;
    let mut previous = String::new();
    let mut before_previous = String::new();
    for token in Lexer::new(sql.as_bytes()) {
        let token = token.map_err(|_| refuse("invalid SQL token"))?;
        if token.token_type == TokenType::TK_NONE {
            continue;
        }
        count += 1;
        if count > 2048 || ended {
            return Err(refuse("token bound or multiple statements"));
        }
        let value = std::str::from_utf8(token.value).map_err(|_| refuse("invalid SQL text"))?;
        let word = value.to_ascii_lowercase();
        if word == "null" && previous == "not" && before_previous != "is" {
            return Err(refuse("NULL tests require lexical IS [NOT] NULL"));
        }
        match word.as_str() {
            "(" => {
                depth += 1;
                if depth > 32 {
                    return Err(refuse("parenthesis depth exceeds 32"));
                }
            }
            ")" => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| refuse("unbalanced parentheses"))?;
            }
            ";" => {
                if depth != 0 {
                    return Err(refuse("invalid semicolon"));
                }
                ended = true;
            }
            "select" => {
                selects += 1;
                if depth != 0 || selects != 1 || count != 1 {
                    return Err(refuse("one outer SELECT only"));
                }
            }
            "from" => {
                froms += 1;
                if depth != 0 || froms != 1 {
                    return Err(refuse("one FROM only"));
                }
            }
            "where" => {
                wheres += 1;
                if depth != 0 || wheres != 1 {
                    return Err(refuse("one WHERE only"));
                }
            }
            "not" => {
                nots += 1;
                if nots > 32 {
                    return Err(refuse("NOT token bound exceeds 32"));
                }
            }
            "id" | "type" | "kind" | "name" | "summary" | "archived" | "children"
            | "current_facet" | "and" | "or" | "in" | "is" | "null" | "true" | "false" | "="
            | "<>" | "," | "0" | "1" => {}
            _ if token.token_type == TokenType::TK_STRING
                && value.starts_with('\'')
                && value.ends_with('\'') => {}
            _ if token.token_type == TokenType::TK_VARIABLE && value.starts_with('?') => {
                let n = &value[1..];
                if n.is_empty()
                    || n.starts_with('0')
                    || !n.bytes().all(|c| c.is_ascii_digit())
                    || n.parse::<usize>().map_or(true, |n| n > 256)
                {
                    return Err(refuse("use numbered ?1..?N parameters"));
                }
            }
            _ => return Err(refuse("unsupported SQL spelling")),
        }
        before_previous = previous;
        previous = word;
    }
    if depth != 0 || selects != 1 || froms != 1 {
        return Err(refuse("incomplete SELECT"));
    }
    Ok(())
}

fn string(raw: &str) -> Result<String> {
    let inner = raw
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .ok_or_else(|| refuse("single-quoted literal required"))?;
    let decoded = inner.replace("''", "'");
    if decoded.chars().count() > 1024 {
        return Err(refuse("text literal exceeds 1024 characters"));
    }
    Ok(decoded)
}

/// Count the complete admitted parser AST iteratively BEFORE recursive lowering.
/// Each enum/struct, Name, operator, Literal, Variable and list container is a
/// node; absent Option and primitive fields are not nodes. Empty lists count.
/// Cmd is root depth 1. Unsupported shapes fail closed here, not after lowering.
fn ast_budget(cmd: &Cmd, max_nodes: usize, max_depth: usize) -> Result<(usize, usize)> {
    enum Node<'a> {
        Cmd(&'a Cmd),
        Select(&'a Select),
        One(&'a OneSelect),
        Column(&'a ResultColumn),
        From(&'a FromClause),
        Table(&'a SelectTable),
        Expr(&'a Expr),
        Leaf,
    }
    let mut stack = vec![(Node::Cmd(cmd), 1)];
    let mut count = 0;
    let mut deepest = 0;
    while let Some((node, depth)) = stack.pop() {
        count += 1;
        deepest = deepest.max(depth);
        if count > max_nodes || depth > max_depth {
            return Err(refuse("AST node/depth bound exceeded"));
        }
        match node {
            Node::Cmd(Cmd::Stmt(Stmt::Select(s))) => {
                stack.push((Node::Leaf, depth + 1));
                stack.push((Node::Select(s), depth + 2));
            }
            Node::Cmd(_) => return Err(refuse("SELECT statement required")),
            Node::Select(s) => {
                if s.with.is_some()
                    || !s.body.compounds.is_empty()
                    || !s.order_by.is_empty()
                    || s.limit.is_some()
                {
                    return Err(refuse("unsupported SELECT clause"));
                }
                stack.push((Node::Leaf, depth + 1)); // SelectBody
                stack.push((Node::Leaf, depth + 1)); // order_by list
                stack.push((Node::Leaf, depth + 2)); // compounds list
                stack.push((Node::One(&s.body.select), depth + 2));
            }
            Node::One(OneSelect::Select {
                distinctness,
                columns,
                from,
                where_clause,
                group_by,
                window_clause,
            }) => {
                if distinctness.is_some() || group_by.is_some() || !window_clause.is_empty() {
                    return Err(refuse("unsupported SELECT shape"));
                }
                stack.push((Node::Leaf, depth + 1)); // columns list
                stack.extend(columns.iter().map(|c| (Node::Column(c), depth + 2)));
                stack.push((Node::Leaf, depth + 1)); // window list
                if let Some(f) = from {
                    stack.push((Node::From(f), depth + 1));
                }
                if let Some(e) = where_clause {
                    stack.push((Node::Expr(e), depth + 1));
                }
            }
            Node::One(_) => return Err(refuse("VALUES/compound select unsupported")),
            Node::Column(ResultColumn::Expr(e, alias)) => {
                stack.push((Node::Expr(e), depth + 1));
                if let Some(alias) = alias {
                    if !matches!(alias, As::ImplicitColumnName(_)) {
                        return Err(refuse("output aliases unsupported"));
                    }
                    stack.push((Node::Leaf, depth + 1));
                    stack.push((Node::Leaf, depth + 2)); // As + Name
                }
            }
            Node::Column(_) => return Err(refuse("star projection unsupported")),
            Node::From(f) => {
                if !f.joins.is_empty() {
                    return Err(refuse("joins unsupported"));
                }
                stack.push((Node::Leaf, depth + 1)); // joins list
                stack.push((Node::Table(&f.select), depth + 1));
            }
            Node::Table(SelectTable::Table(q, None, None))
                if q.db_name.is_none() && q.alias.is_none() =>
            {
                stack.push((Node::Leaf, depth + 1));
                stack.push((Node::Leaf, depth + 2)); // QualifiedName + Name
            }
            Node::Table(_) => return Err(refuse("one unqualified children source required")),
            Node::Expr(e) => match e {
                Expr::Name(_) | Expr::Id(_) => stack.push((Node::Leaf, depth + 1)),
                Expr::Literal(_) | Expr::Variable(_) => stack.push((Node::Leaf, depth + 1)),
                Expr::Parenthesized(es) => {
                    stack.push((Node::Leaf, depth + 1));
                    stack.extend(es.iter().map(|e| (Node::Expr(e), depth + 2)));
                }
                Expr::Unary(_, e) => {
                    stack.push((Node::Leaf, depth + 1));
                    stack.push((Node::Expr(e), depth + 1));
                }
                Expr::Binary(a, _, b) => {
                    stack.push((Node::Leaf, depth + 1));
                    stack.push((Node::Expr(a), depth + 1));
                    stack.push((Node::Expr(b), depth + 1));
                }
                Expr::IsNull(e) | Expr::NotNull(e) => stack.push((Node::Expr(e), depth + 1)),
                Expr::InList { lhs, rhs, .. } => {
                    stack.push((Node::Expr(lhs), depth + 1));
                    stack.push((Node::Leaf, depth + 1));
                    stack.extend(rhs.iter().map(|e| (Node::Expr(e), depth + 2)));
                }
                Expr::FunctionCall {
                    name,
                    distinctness,
                    args,
                    order_by,
                    within_group,
                    filter_over,
                } => {
                    if !name.as_str().eq_ignore_ascii_case("current_facet")
                        || distinctness.is_some()
                        || !order_by.is_empty()
                        || !within_group.is_empty()
                        || filter_over.filter_clause.is_some()
                        || filter_over.over_clause.is_some()
                    {
                        return Err(refuse("unsupported function field/tail"));
                    }
                    stack.push((Node::Leaf, depth + 1)); // name
                    stack.push((Node::Leaf, depth + 1)); // args list
                    stack.extend(args.iter().map(|e| (Node::Expr(e), depth + 2)));
                    stack.push((Node::Leaf, depth + 1)); // order_by list
                    stack.push((Node::Leaf, depth + 1)); // within_group list
                    stack.push((Node::Leaf, depth + 1)); // FunctionTail
                }
                _ => return Err(refuse("unsupported AST expression")),
            },
            Node::Leaf => {}
        }
    }
    Ok((count, deepest))
}

struct Lower<'a> {
    params: &'a [Scalar],
    used: BTreeMap<usize, bool>,
    keys: BTreeSet<String>,
}
impl Lower<'_> {
    fn field(&mut self, expr: &Expr, depth: usize) -> Result<Field> {
        if depth > 32 {
            return Err(refuse("lowering depth exceeded"));
        }
        match expr {
            Expr::Parenthesized(es) if es.len() == 1 => self.field(&es[0], depth + 1),
            Expr::Name(n) | Expr::Id(n) => {
                let name = n.as_str().to_ascii_lowercase();
                if ["id", "type", "kind", "name", "summary", "archived"].contains(&name.as_str()) {
                    Ok(Field::Raw(name))
                } else {
                    Err(refuse("unsupported field"))
                }
            }
            Expr::FunctionCall {
                name,
                distinctness,
                args,
                order_by,
                within_group,
                filter_over,
            } if name.as_str().eq_ignore_ascii_case("current_facet")
                && distinctness.is_none()
                && args.len() == 1
                && order_by.is_empty()
                && within_group.is_empty()
                && filter_over.filter_clause.is_none()
                && filter_over.over_clause.is_none() =>
            {
                let Expr::Literal(Literal::String(raw)) = &*args[0] else {
                    return Err(refuse("current_facet requires one literal key"));
                };
                let key = string(raw)?;
                if key.is_empty() || key.chars().count() > 120 {
                    return Err(refuse("facet key bound is 1..120 characters"));
                }
                crate::domain_transaction::assert_open_facet_key("sql_write", &key)
                    .map_err(|_| refuse("reserved facet key"))?;
                self.keys.insert(key.clone());
                Ok(Field::Facet(key))
            }
            _ => Err(refuse("unsupported field/accessor shape")),
        }
    }
    fn atom(&mut self, expr: &Expr, boolean: bool, depth: usize) -> Result<Scalar> {
        if depth > 32 {
            return Err(refuse("lowering depth exceeded"));
        }
        let atom = match expr {
            Expr::Parenthesized(es) if es.len() == 1 => {
                return self.atom(&es[0], boolean, depth + 1)
            }
            Expr::Literal(Literal::Null) => Scalar::Null,
            Expr::Literal(Literal::String(s)) if !boolean => Scalar::Text(string(s)?),
            Expr::Literal(Literal::True) if boolean => Scalar::Boolean(true),
            Expr::Literal(Literal::False) if boolean => Scalar::Boolean(false),
            Expr::Literal(Literal::Numeric(s)) if boolean && (s == "0" || s == "1") => {
                Scalar::Boolean(s == "1")
            }
            Expr::Variable(variable)
                if variable.numbered && variable.name.is_none() && variable.col_type.is_none() =>
            {
                let index = variable.index.get() as usize;
                if self
                    .used
                    .insert(index, boolean)
                    .is_some_and(|old| old != boolean)
                {
                    return Err(refuse("parameter reused in incompatible contexts"));
                }
                self.params
                    .get(index - 1)
                    .cloned()
                    .ok_or_else(|| refuse("parameter slot missing"))?
            }
            _ => return Err(refuse("incompatible or computed operand")),
        };
        if !matches!(
            (&atom, boolean),
            (Scalar::Null, _) | (Scalar::Text(_), false) | (Scalar::Boolean(_), true)
        ) {
            return Err(refuse("incompatible operand type"));
        }
        Ok(atom)
    }
    fn predicate(&mut self, expr: &Expr, depth: usize) -> Result<Predicate> {
        if depth > 32 {
            return Err(refuse("lowering depth exceeded"));
        }
        match expr {
            Expr::Parenthesized(es) if es.len() == 1 => self.predicate(&es[0], depth + 1),
            Expr::Unary(UnaryOperator::Not, e) => {
                Ok(Predicate::Not(Box::new(self.predicate(e, depth + 1)?)))
            }
            Expr::Binary(a, op @ (Operator::And | Operator::Or), b) => {
                let a = Box::new(self.predicate(a, depth + 1)?);
                let b = Box::new(self.predicate(b, depth + 1)?);
                Ok(if *op == Operator::And {
                    Predicate::And(a, b)
                } else {
                    Predicate::Or(a, b)
                })
            }
            Expr::Binary(a, op @ (Operator::Equals | Operator::NotEquals), b) => {
                let field = self.field(a, depth + 1)?;
                let atom = self.atom(b, field.boolean(), depth + 1)?;
                Ok(Predicate::Compare(field, atom, *op == Operator::NotEquals))
            }
            Expr::Binary(a, op @ (Operator::Is | Operator::IsNot), b)
                if matches!(&**b, Expr::Literal(Literal::Null)) =>
            {
                let field = self.field(a, depth + 1)?;
                Ok(Predicate::Null(field, *op == Operator::IsNot))
            }
            Expr::IsNull(e) => Ok(Predicate::Null(self.field(e, depth + 1)?, false)),
            Expr::NotNull(e) => Ok(Predicate::Null(self.field(e, depth + 1)?, true)),
            Expr::InList { lhs, not, rhs } if !rhs.is_empty() && rhs.len() <= 256 => {
                let field = self.field(lhs, depth + 1)?;
                let atoms = rhs
                    .iter()
                    .map(|e| self.atom(e, field.boolean(), depth + 1))
                    .collect::<Result<_>>()?;
                Ok(Predicate::In(field, atoms, *not))
            }
            _ => Err(refuse("unsupported predicate")),
        }
    }
}

pub(super) fn compile(sql: &str, params: &[Scalar]) -> Result<Program> {
    preflight(sql)?;
    if params.len() > 256 {
        return Err(refuse("parameter bound exceeds 256"));
    }
    let mut parser = Parser::new(sql.as_bytes());
    let cmd = parser
        .next()
        .transpose()
        .map_err(|_| refuse("invalid SELECT syntax"))?
        .ok_or_else(|| refuse("empty statement"))?;
    if parser.next().is_some() {
        return Err(refuse("multiple statements"));
    }
    ast_budget(&cmd, 1024, 32)?;
    let Cmd::Stmt(Stmt::Select(select)) = cmd else {
        return Err(refuse("SELECT required"));
    };
    if select.with.is_some()
        || !select.body.compounds.is_empty()
        || !select.order_by.is_empty()
        || select.limit.is_some()
    {
        return Err(refuse("unsupported SELECT clause"));
    }
    let OneSelect::Select {
        distinctness,
        columns,
        from,
        where_clause,
        group_by,
        window_clause,
    } = select.body.select
    else {
        return Err(refuse("SELECT required"));
    };
    if distinctness.is_some()
        || columns.len() != 1
        || group_by.is_some()
        || !window_clause.is_empty()
    {
        return Err(refuse("unsupported SELECT shape"));
    }
    let ResultColumn::Expr(expr, alias) = &columns[0] else {
        return Err(refuse("project unaliased id only"));
    };
    if !matches!(&**expr,Expr::Name(n)|Expr::Id(n) if n.as_str().eq_ignore_ascii_case("id"))
        || !matches!(alias, None | Some(As::ImplicitColumnName(_)))
    {
        return Err(refuse("project unaliased id only"));
    }
    // The parser's implicit output name preserves source trivia. The bare Expr
    // is already verified id; this derived diagnostic label is not an alias.

    let from = from.ok_or_else(|| refuse("FROM children required"))?;
    if !from.joins.is_empty()
        || !matches!(&*from.select,SelectTable::Table(n,None,None) if n.db_name.is_none() && n.alias.is_none() && n.name.as_str().eq_ignore_ascii_case("children"))
    {
        return Err(refuse("one unqualified children source required"));
    }
    let mut lower = Lower {
        params,
        used: BTreeMap::new(),
        keys: BTreeSet::new(),
    };
    let predicate = match where_clause {
        Some(e) => lower.predicate(&e, 1)?,
        None => Predicate::All,
    };
    if lower.used.keys().copied().collect::<Vec<_>>() != (1..=params.len()).collect::<Vec<_>>() {
        return Err(refuse(
            "parameters must be exactly contiguous numbered slots",
        ));
    }
    Ok(Program {
        predicate,
        keys: lower.keys,
        parameter_contexts: lower.used,
    })
}

impl Predicate {
    pub(super) fn eval(
        &self,
        raw: &BTreeMap<String, Scalar>,
        facets: &BTreeMap<String, Scalar>,
    ) -> Truth {
        let value = |field: &Field| {
            match field {
                Field::Raw(k) => raw.get(k),
                Field::Facet(k) => facets.get(k),
            }
            .unwrap_or(&Scalar::Null)
            .clone()
        };
        let equals = |a: &Scalar, b: &Scalar| {
            if matches!(a, Scalar::Null) || matches!(b, Scalar::Null) {
                Truth::Unknown
            } else if a == b {
                Truth::True
            } else {
                Truth::False
            }
        };
        match self {
            Self::All => Truth::True,
            Self::Compare(f, a, not) => {
                let t = equals(&value(f), a);
                if *not {
                    t.not()
                } else {
                    t
                }
            }
            Self::Null(f, not) => {
                let t = if matches!(value(f), Scalar::Null) {
                    Truth::True
                } else {
                    Truth::False
                };
                if *not {
                    t.not()
                } else {
                    t
                }
            }
            Self::In(f, atoms, not) => {
                let v = value(f);
                let t = atoms.iter().fold(Truth::False, |t, a| t.or(equals(&v, a)));
                if *not {
                    t.not()
                } else {
                    t
                }
            }
            Self::And(a, b) => a.eval(raw, facets).and(b.eval(raw, facets)),
            Self::Or(a, b) => a.eval(raw, facets).or(b.eval(raw, facets)),
            Self::Not(e) => e.eval(raw, facets).not(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse_ast(sql: &str) -> Cmd {
        Parser::new(sql.as_bytes()).next().unwrap().unwrap()
    }
    #[test]
    fn exhaustive_three_valued_truth_and_closed_expression_forms() {
        use Truth::{False as F, True as T, Unknown as U};
        let states = [T, F, U];
        let and = [[T, F, U], [F, F, F], [U, F, U]];
        let or = [[T, T, T], [T, F, U], [T, U, U]];
        let expressions = ["id='t'", "id='f'", "summary='x'"];
        let raw = BTreeMap::from([
            ("id".into(), Scalar::Text("t".into())),
            ("summary".into(), Scalar::Null),
            ("kind".into(), Scalar::Null),
            ("archived".into(), Scalar::Boolean(false)),
        ]);
        for i in 0..3 {
            assert_eq!(states[i].not(), [F, T, U][i]);
            for j in 0..3 {
                assert_eq!(states[i].and(states[j]), and[i][j]);
                assert_eq!(states[i].or(states[j]), or[i][j]);
                for (op, expected) in [("AND", and[i][j]), ("OR", or[i][j])] {
                    let sql = format!(
                        "SELECT id FROM children WHERE ({}) {op} ({})",
                        expressions[i], expressions[j]
                    );
                    assert_eq!(
                        compile(&sql, &[])
                            .unwrap()
                            .predicate
                            .eval(&raw, &BTreeMap::new()),
                        expected,
                        "{sql}"
                    );
                }
            }
        }
        for (atom, expected) in [
            ("id='t' OR id='f' AND summary='x'", T),
            ("(id='t' OR id='f') AND summary='x'", U),
            ("kind IS NULL", T),
            ("kind IS NOT NULL", F),
            ("kind NOT IN ('x',NULL)", U),
            ("id IN ('t',NULL)", T),
            ("id NOT IN ('x',NULL)", U),
            ("current_facet('absent') <> 'x'", U),
            ("NOT current_facet('absent')='x'", U),
            ("current_facet('absent') IS NULL", T),
        ] {
            assert_eq!(
                compile(&format!("SELECT id FROM children WHERE {atom}"), &[])
                    .unwrap()
                    .predicate
                    .eval(&raw, &BTreeMap::new()),
                expected,
                "{atom}"
            );
        }
        for sql in [
            "SELECT id FROM children WHERE name REGEXP 'x'",
            "SELECT id FROM children WHERE name BETWEEN 'a' AND 'z'",
            "SELECT id FROM children WHERE name||'x'='x'",
            "SELECT id FROM children WHERE archived+1=1",
            "SELECT id FROM children WHERE archived&1=0",
            "SELECT row_number() OVER () FROM children",
            "SELECT id FROM children WINDOW w AS ()",
            "SELECT id FROM children WHERE abs(1)=1",
            "SELECT id FROM children WHERE current_facet(DISTINCT 'k')='v'",
            "SELECT id FROM children WHERE current_facet('k') FILTER(WHERE TRUE)='v'",
            "SELECT id FROM children WHERE current_facet('k') OVER ()='v'",
            "SELECT id FROM children WHERE main.current_facet('k')='v'",
            "SELECT id FROM children WHERE archived IS NOT FALSE",
            "SELECT id FROM children WHERE name IS 'x'",
            "SELECT id FROM children WHERE name != 'x'",
            "SELECT id FROM children WHERE name=:p",
            "SELECT id FROM children WHERE name=?",
            "SELECT id FROM children WHERE name=?2",
            "SELECT id FROM children WHERE name=X'00'",
            "SELECT id FROM children WHERE name=CURRENT_TIMESTAMP",
            "SELECT id FROM children WHERE name COLLATE NOCASE='x'",
            "SELECT id FROM children WHERE id=id",
            "SELECT id FROM children WHERE unknown='x'",
            "SELECT id FROM children WHERE native_raw='x'",
            "SELECT id FROM children HAVING TRUE",
            "SELECT id FROM children INDEXED BY index_name",
            "SELECT id FROM children AS c",
        ] {
            assert!(compile(sql, &[]).is_err(), "{sql}");
        }
    }
    #[test]
    fn lexical_null_tests_and_projection_trivia_are_exact() {
        for sql in ["SELECT id /* name trivia */ FROM children WHERE summary IS NULL", "-- start\nSELECT id -- projection trivia\nFROM children WHERE summary IS /*between*/ NOT NULL;"] {compile(sql,&[]).unwrap();}
        for sql in [
            "SELECT id FROM children WHERE summary NOT NULL",
            "SELECT id FROM children WHERE summary NOT /* gap */ NULL",
            "SELECT id FROM children WHERE summary IS TRUE",
            "SELECT id AS id FROM children",
            "SELECT id FROM children id",
            "SELECT \"id\" FROM children",
        ] {
            assert!(compile(sql, &[]).is_err(), "{sql}");
        }
        // The locked lexer/parser treats a block comment through EOF as trivia.
        parse_ast("SELECT id FROM children /* through EOF");
        compile("SELECT id FROM children /* through EOF", &[]).unwrap();
        assert!(compile("SELECT id FROM children WHERE name='unterminated", &[]).is_err());
        let cmd = parse_ast("SELECT id /* projection trivia */ FROM children");
        let Cmd::Stmt(Stmt::Select(s)) = cmd else {
            panic!("select")
        };
        let OneSelect::Select { columns, .. } = s.body.select else {
            panic!("select")
        };
        assert!(
            matches!(&columns[0],ResultColumn::Expr(e,Some(As::ImplicitColumnName(name))) if matches!(&**e,Expr::Id(_)|Expr::Name(_)) && name.as_str().contains("/* projection trivia */"))
        );
    }
    #[test]
    fn iterative_ast_counts_root_structures_lists_and_exact_boundaries() {
        let cmd = parse_ast("SELECT id FROM children");
        assert_eq!(ast_budget(&cmd, 1024, 32).unwrap(), (19, 9));
        assert!(ast_budget(&cmd, 18, 32).is_err());
        assert!(ast_budget(&cmd, 19, 8).is_err());
        let list = |n| std::iter::repeat_n("'x'", n).collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT id FROM children WHERE id IN ({}) OR id IN ({}) OR summary IS NULL",
            list(256),
            list(237)
        );
        // Lexical IS NULL is normalized to Binary(Is, field, Literal::Null)
        // by this parser. Admitted examples here consequently have odd counts.
        assert_eq!(ast_budget(&parse_ast(&sql), 1024, 32).unwrap().0, 1023);
        compile(&sql, &[]).unwrap();
        let overflow = format!(
            "SELECT id FROM children WHERE id IN ({}) OR id IN ({}) OR summary IS NULL",
            list(256),
            list(238)
        );
        assert_eq!(ast_budget(&parse_ast(&overflow), 2048, 32).unwrap().0, 1025);
        assert!(compile(&overflow, &[]).is_err());
        // Exercise the exact walker bound with the parser's postfix AST form,
        // independently of lexical admission: v1 still refuses ISNULL spelling.
        let exact = format!(
            "SELECT id FROM children WHERE id IN ({}) OR id IN ({}) OR summary ISNULL",
            list(256),
            list(239)
        );
        let exact = parse_ast(&exact);
        assert_eq!(ast_budget(&exact, 1024, 32).unwrap().0, 1024);
        assert!(ast_budget(&exact, 1023, 32).is_err());
        let nested = format!(
            "SELECT id FROM children WHERE {}id='x'{}",
            "(".repeat(12),
            ")".repeat(12)
        );
        assert_eq!(ast_budget(&parse_ast(&nested), 1024, 32).unwrap().1, 32);
        compile(&nested, &[]).unwrap();
        assert!(compile(&nested.replace("WHERE", "WHERE NOT"), &[]).is_err());
        assert!(compile(
            &format!(
                "SELECT id FROM children WHERE {}summary IS NULL{}",
                "(".repeat(33),
                ")".repeat(33)
            ),
            &[]
        )
        .is_err());
    }
    #[test]
    fn binary_three_valued_logic_and_literal_decoding() {
        let raw = BTreeMap::from([
            ("archived".into(), Scalar::Boolean(false)),
            ("name".into(), Scalar::Text("O'Brien".into())),
            ("summary".into(), Scalar::Null),
        ]);
        let facets = BTreeMap::from([("owner's lane".into(), Scalar::Text("Ready".into()))]);
        for (where_sql, expected) in [
            ("name='O''Brien' AND archived=false", Truth::True),
            ("archived=0", Truth::True),
            ("summary <> 'x'", Truth::Unknown),
            ("NOT summary IN ('x',NULL)", Truth::Unknown),
            ("summary <> 'x' OR summary IS NULL", Truth::True),
            ("current_facet('owner''s lane')='Ready'", Truth::True),
            ("current_facet('owner''s lane')='ready'", Truth::False),
        ] {
            assert_eq!(
                compile(&format!("SELECT id FROM children WHERE {where_sql}"), &[])
                    .unwrap()
                    .predicate
                    .eval(&raw, &facets),
                expected,
                "{where_sql}"
            );
        }
        for sql in [
            "archived='false'",
            "name=1",
            "archived IS FALSE",
            "1",
            "TRUE",
            "name=name",
            "current_facet(?1)='x'",
            "name != 'x'",
            "name LIKE 'x'",
            "name COLLATE NOCASE='x'",
        ] {
            assert!(
                compile(&format!("SELECT id FROM children WHERE {sql}"), &[]).is_err(),
                "{sql}"
            );
        }
    }
    #[test]
    fn parameters_are_numbered_contiguous_and_context_typed() {
        compile(
            "SELECT id FROM children WHERE name=?1 OR name=?1",
            &[Scalar::Text("x".into())],
        )
        .unwrap();
        for (sql, p) in [
            (
                "SELECT id FROM children WHERE name=?2",
                vec![Scalar::Null, Scalar::Null],
            ),
            (
                "SELECT id FROM children WHERE name=?1 OR archived=?1",
                vec![Scalar::Null],
            ),
            ("SELECT id FROM children WHERE name=?", vec![Scalar::Null]),
            ("SELECT id FROM children WHERE name=:x", vec![Scalar::Null]),
        ] {
            assert!(compile(sql, &p).is_err());
        }
        let program =
            compile("SELECT id FROM children WHERE archived=?1", &[Scalar::Null]).unwrap();
        assert_eq!(program.parameter_contexts, BTreeMap::from([(1, true)]));
    }
}
