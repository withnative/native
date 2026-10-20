//! Pure formula grammar for the gated v2 budget arithmetic provider.
//!
//! Gated like the rest of the v2 kernel probe surface (see `crate::v2_budget`).
//! Nothing here is reachable from the default build: no storage, no SQL
//! surface, no migration, and no `crate::schema` change.
//!
//! The grammar is deliberately tiny and closed. It has no function calls
//! beyond `SUM`, no strings, no booleans, no names, no cell ranges outside
//! `A1:Z99`, and no application-level features:
//!
//! ```text
//! formula   := expr
//! expr      := term (('+' | '-') term)*
//! term      := unary (('*' | '/') unary)*
//! unary     := ('+' | '-') unary | primary
//! primary   := number | cell | 'SUM' '(' cell ':' cell ')' | '(' expr ')'
//! number    := digits ('.' digits)? | '.' digits
//! cell      := column row          ; column A-Z, row 1-99
//! ```
//!
//! Whitespace is insignificant between tokens. The lexer and parser are pure:
//! they allocate only the token buffer and the returned AST, consult no global
//! state, perform no I/O, and cannot recurse without bound (both the token
//! count and the nesting depth are hard-capped; see the constants on
//! [`super`]).

use super::{MAX_NESTING_DEPTH, MAX_RANGE_MEMBERS, MAX_TOKENS_PER_EXPRESSION};

/// Largest single-letter column index (`Z`).
pub(crate) const MAX_COL: u8 = b'Z' - b'A';
/// Largest row number (`99`).
pub(crate) const MAX_ROW: u8 = 99;

/// A normalised sheet address: a column `A`-`Z` and a row `1`-`99`.
///
/// Normalisation means the single canonical spelling of a cell: the column is
/// upper-case and the row has no leading zeros, so `a01`, `A01` and `A1` all
/// denote the same address. Parsing accepts lower-case input for convenience;
/// the canonical `Display` form is always upper-case.
///
/// Ordering is row-major (row first, then column), matching how a spreadsheet
/// is read and making the map iteration order of an evaluation deterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address {
    pub(crate) col: u8,
    pub(crate) row: u8,
}

impl Address {
    /// Parse a canonical-or-lowercase address. Returns `None` for anything
    /// that is not exactly one `A`-`Z` letter followed by one to three digits
    /// forming a row in `1`-`99`.
    pub fn parse(raw: &str) -> Option<Address> {
        let bytes = raw.as_bytes();
        if !(2..=4).contains(&bytes.len()) {
            return None;
        }
        let first = bytes[0];
        if !first.is_ascii_alphabetic() {
            return None;
        }
        let col = first.to_ascii_uppercase().wrapping_sub(b'A');
        if col > MAX_COL {
            return None;
        }
        if !bytes[1..].iter().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let row: u32 = raw[1..].parse().ok()?;
        if !(1..=u32::from(MAX_ROW)).contains(&row) {
            return None;
        }
        Some(Address {
            col,
            row: row as u8,
        })
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let letter = (b'A' + self.col) as char;
        write!(f, "{letter}{}", self.row)
    }
}

impl Ord for Address {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.row
            .cmp(&other.row)
            .then_with(|| self.col.cmp(&other.col))
    }
}

impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// A rectangular inclusive cell range, normalised so `start` is the top-left
/// and `end` is the bottom-right corner. A reversed authoring (for example
/// `SUM(B3:A1)`) is normalised rather than rejected.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Range {
    pub(crate) start: Address,
    pub(crate) end: Address,
}

impl Range {
    pub(crate) fn new(a: Address, b: Address) -> Range {
        let row_start = a.row.min(b.row);
        let row_end = a.row.max(b.row);
        let col_start = a.col.min(b.col);
        let col_end = a.col.max(b.col);
        Range {
            start: Address {
                col: col_start,
                row: row_start,
            },
            end: Address {
                col: col_end,
                row: row_end,
            },
        }
    }

    /// Number of cells the range covers, counting the bounding rectangle.
    pub(crate) fn members(&self) -> usize {
        let rows = usize::from(self.end.row - self.start.row) + 1;
        let cols = usize::from(self.end.col - self.start.col) + 1;
        rows * cols
    }

    /// Row-major iteration over the covered cells.
    pub(crate) fn cells(&self) -> impl Iterator<Item = Address> + '_ {
        (self.start.row..=self.end.row).flat_map(move |row| {
            (self.start.col..=self.end.col).map(move |col| Address { col, row })
        })
    }
}

/// The parsed arithmetic expression tree. Pure data; evaluation lives in
/// [`super`].
#[derive(Debug, Clone)]
pub(crate) enum Expr {
    Number(f64),
    Cell(Address),
    Sum(Range),
    Neg(Box<Expr>),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    Div(Box<Expr>, Box<Expr>),
}

/// A parser-level failure. [`super`] attaches the owning cell address and maps
/// these onto the public error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParseError {
    /// The expression carried no tokens.
    Empty,
    /// A character that cannot begin any token.
    UnexpectedChar(char),
    /// A letter run that is neither `SUM(...)` nor a single-letter cell.
    UnknownIdentifier(String),
    /// A token that looks like a cell but is outside `A1`-`Z99`.
    InvalidAddress(String),
    /// A numeric literal that is not `digits(.digits)?`.
    MalformedNumber(String),
    /// A numeric literal that overflows `f64`.
    NonFinite,
    /// The expression lexed to more than `MAX_TOKENS_PER_EXPRESSION` tokens.
    TooManyTokens { count: usize, max: usize },
    /// Parenthesis or unary nesting exceeded `MAX_NESTING_DEPTH`.
    NestingTooDeep { depth: usize, max: usize },
    /// A `SUM` range covered more than `MAX_RANGE_MEMBERS` cells.
    RangeTooLarge { members: usize, max: usize },
    /// A primary was expected but the next token was not one.
    ExpectedExpression,
    /// A specific token was expected.
    ExpectedToken(&'static str),
    /// Input ended in the middle of an expression.
    UnexpectedEnd,
    /// A complete expression was followed by more input.
    TrailingInput,
}

#[derive(Debug, Clone)]
enum Tok {
    Number(f64),
    Cell(Address),
    Sum,
    Plus,
    Minus,
    Star,
    Slash,
    LParen,
    RParen,
    Colon,
}

/// Lex and parse one expression body (the caller has already removed any
/// optional leading `=`). Blank input is [`ParseError::Empty`].
pub(crate) fn parse(input: &str) -> Result<Expr, ParseError> {
    if input.trim().is_empty() {
        return Err(ParseError::Empty);
    }
    let tokens = lex(input)?;
    let mut parser = Parser {
        tokens,
        pos: 0,
        depth: 0,
    };
    let expr = parser.parse_expr()?;
    if parser.pos != parser.tokens.len() {
        return Err(ParseError::TrailingInput);
    }
    Ok(expr)
}

fn lex(input: &str) -> Result<Vec<Tok>, ParseError> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '+' => {
                tokens.push(Tok::Plus);
                i += 1;
            }
            '-' => {
                tokens.push(Tok::Minus);
                i += 1;
            }
            '*' => {
                tokens.push(Tok::Star);
                i += 1;
            }
            '/' => {
                tokens.push(Tok::Slash);
                i += 1;
            }
            '(' => {
                tokens.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Tok::RParen);
                i += 1;
            }
            ':' => {
                tokens.push(Tok::Colon);
                i += 1;
            }
            c if c.is_ascii_digit() || c == '.' => {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                    i += 1;
                }
                let raw: String = chars[start..i].iter().collect();
                let parts: Vec<&str> = raw.split('.').collect();
                let valid = match parts.as_slice() {
                    [intg] => !intg.is_empty() && all_digits(intg),
                    [intg, frac] => !frac.is_empty() && all_digits(frac) && all_digits(intg),
                    _ => false,
                };
                if !valid {
                    return Err(ParseError::MalformedNumber(raw));
                }
                let value: f64 = raw
                    .parse()
                    .map_err(|_| ParseError::MalformedNumber(raw.clone()))?;
                if !value.is_finite() {
                    return Err(ParseError::NonFinite);
                }
                tokens.push(Tok::Number(value));
            }
            c if c.is_ascii_alphabetic() => {
                let start = i;
                while i < chars.len() && chars[i].is_ascii_alphabetic() {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                if word.eq_ignore_ascii_case("SUM") && next_non_space(&chars, i) == Some('(') {
                    tokens.push(Tok::Sum);
                } else if word.len() == 1 && chars.get(i).is_some_and(char::is_ascii_digit) {
                    while i < chars.len() && chars[i].is_ascii_digit() {
                        i += 1;
                    }
                    let raw: String = chars[start..i].iter().collect();
                    match Address::parse(&raw) {
                        Some(address) => tokens.push(Tok::Cell(address)),
                        None => return Err(ParseError::InvalidAddress(raw)),
                    }
                } else {
                    return Err(ParseError::UnknownIdentifier(word));
                }
            }
            other => return Err(ParseError::UnexpectedChar(other)),
        }
        if tokens.len() > MAX_TOKENS_PER_EXPRESSION {
            return Err(ParseError::TooManyTokens {
                count: tokens.len(),
                max: MAX_TOKENS_PER_EXPRESSION,
            });
        }
    }
    Ok(tokens)
}

fn all_digits(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_digit())
}

fn next_non_space(chars: &[char], mut i: usize) -> Option<char> {
    while i < chars.len() {
        if !chars[i].is_whitespace() {
            return Some(chars[i]);
        }
        i += 1;
    }
    None
}

struct Parser {
    tokens: Vec<Tok>,
    pos: usize,
    depth: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos)
    }

    fn enter(&mut self) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > MAX_NESTING_DEPTH {
            return Err(ParseError::NestingTooDeep {
                depth: self.depth,
                max: MAX_NESTING_DEPTH,
            });
        }
        Ok(())
    }

    fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_term()?;
        loop {
            match self.peek() {
                Some(Tok::Plus) => {
                    self.pos += 1;
                    let rhs = self.parse_term()?;
                    lhs = Expr::Add(Box::new(lhs), Box::new(rhs));
                }
                Some(Tok::Minus) => {
                    self.pos += 1;
                    let rhs = self.parse_term()?;
                    lhs = Expr::Sub(Box::new(lhs), Box::new(rhs));
                }
                _ => return Ok(lhs),
            }
        }
    }

    fn parse_term(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_unary()?;
        loop {
            match self.peek() {
                Some(Tok::Star) => {
                    self.pos += 1;
                    let rhs = self.parse_unary()?;
                    lhs = Expr::Mul(Box::new(lhs), Box::new(rhs));
                }
                Some(Tok::Slash) => {
                    self.pos += 1;
                    let rhs = self.parse_unary()?;
                    lhs = Expr::Div(Box::new(lhs), Box::new(rhs));
                }
                _ => return Ok(lhs),
            }
        }
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        match self.peek() {
            Some(Tok::Minus) => {
                self.pos += 1;
                self.enter()?;
                let inner = self.parse_unary()?;
                self.depth -= 1;
                Ok(Expr::Neg(Box::new(inner)))
            }
            Some(Tok::Plus) => {
                self.pos += 1;
                self.enter()?;
                let inner = self.parse_unary()?;
                self.depth -= 1;
                Ok(inner)
            }
            _ => self.parse_primary(),
        }
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        match self.peek() {
            Some(Tok::Number(value)) => {
                let value = *value;
                self.pos += 1;
                Ok(Expr::Number(value))
            }
            Some(Tok::Cell(address)) => {
                let address = *address;
                self.pos += 1;
                Ok(Expr::Cell(address))
            }
            Some(Tok::Sum) => {
                self.pos += 1;
                self.parse_sum()
            }
            Some(Tok::LParen) => {
                self.pos += 1;
                self.enter()?;
                let inner = self.parse_expr()?;
                self.depth -= 1;
                self.expect(&Tok::RParen, ")")?;
                Ok(inner)
            }
            Some(_) => Err(ParseError::ExpectedExpression),
            None => Err(ParseError::UnexpectedEnd),
        }
    }

    fn parse_sum(&mut self) -> Result<Expr, ParseError> {
        self.expect(&Tok::LParen, "(")?;
        let start = self.expect_address()?;
        self.expect(&Tok::Colon, ":")?;
        let end = self.expect_address()?;
        self.expect(&Tok::RParen, ")")?;
        let range = Range::new(start, end);
        let members = range.members();
        if members > MAX_RANGE_MEMBERS {
            return Err(ParseError::RangeTooLarge {
                members,
                max: MAX_RANGE_MEMBERS,
            });
        }
        Ok(Expr::Sum(range))
    }

    fn expect(&mut self, expected: &Tok, what: &'static str) -> Result<(), ParseError> {
        match self.peek() {
            Some(token) if std::mem::discriminant(token) == std::mem::discriminant(expected) => {
                self.pos += 1;
                Ok(())
            }
            _ => Err(ParseError::ExpectedToken(what)),
        }
    }

    fn expect_address(&mut self) -> Result<Address, ParseError> {
        match self.peek() {
            Some(Tok::Cell(address)) => {
                let address = *address;
                self.pos += 1;
                Ok(address)
            }
            _ => Err(ParseError::ExpectedToken("a cell reference")),
        }
    }
}
