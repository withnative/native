//! Gated v2 budget arithmetic provider prototype (proof slice 1).
//!
//! Compiled only under `cfg(any(test, feature = "v2-kernel-probe"))` (see the
//! gated `mod` declaration in the crate root). Nothing here touches the
//! default build: no v1 schema change, no migration, no additions to
//! `crate::schema::DDL_STATEMENTS`, and no MCP tool surface. It is a pure,
//! host-owned provider with no I/O, no randomness, and no process state.
//!
//! # What this is
//!
//! A whole-sheet arithmetic evaluator for a small, closed formula language:
//! literal numbers, `A1` cell references, `+ - * /` with ordinary precedence,
//! parentheses, and rectangular `SUM(A1:B3)` ranges. Every cell is evaluated
//! from the input map with memoisation and dependency traversal, so forward
//! references resolve and a reference chain is computed once.
//!
//! # What this is not
//!
//! **This is not exact currency accounting.** Values are finite IEEE-754
//! `f64`; binary floating point cannot represent most decimal money amounts
//! exactly. This prototype exists to prove the arithmetic and dependency
//! runtime with tight caps, not to be a ledger. There is no `eval`, no
//! JavaScript, no network access, no CEL, and no reuse of the parked
//! parser-memory (4a) path: the grammar is hand-written and closed.
//!
//! # Semantics
//!
//! - A cell's input value is an expression. An optional leading `=` is
//!   stripped before parsing; `1+2` and `=1+2` are the same formula. A value
//!   with no operator is simply a literal number (`"5"` evaluates to `5`).
//! - The surrounding whitespace of a cell value is trimmed; the expression
//!   body is otherwise parsed with insignificant internal whitespace.
//! - **Blank cells are not zero.** A reference (including one inside a `SUM`
//!   range) to an address that is absent from the input map is
//!   [`BudgetError::MissingReference`]. A call to a cell that is present with
//!   a formula of `0` is an ordinary zero. Cell display labels are a separate
//!   surface concern and are not part of this provider.
//! - `SUM(A1:B3)` sums the rectangular bounding box; a reversed authoring
//!   (`SUM(B3:A1)`) is normalised to the same box.
//! - Errors are deterministic: input entries are processed in a
//!   deterministic order (sorted by the raw address string), the sheet is
//!   evaluated in row-major address order, and the first error encountered is
//!   returned.
//! - Arithmetic is finite-only: the first non-finite intermediate or result
//!   (for example an overflowed product or a summation that reaches `inf`) is
//!   [`BudgetError::NonFiniteResult`] attributed to the cell being evaluated.
//!   An overflowed subexpression never silently collapses to `0` through
//!   `1 / inf` or `inf - inf`.
//!
//! # Admission caps (checked before evaluation)
//!
//! All caps are counted at admission, before any arithmetic is evaluated. The
//! limits are intentionally small so a hostile or accidental oversized sheet
//! is refused rather than evaluated:
//!
//! - [`MAX_CELLS`] cells in the sheet;
//! - [`MAX_FORMULA_BYTES`] bytes for any one cell expression;
//! - [`MAX_TOTAL_EXPRESSION_BYTES`] bytes across all expressions;
//! - addresses restricted to columns `A`-`Z` and rows `1`-`99`;
//! - [`MAX_NESTING_DEPTH`] parser parenthesis/unary nesting;
//! - [`MAX_TOKENS_PER_EXPRESSION`] lexed tokens per expression;
//! - [`MAX_RANGE_MEMBERS`] cells in any single `SUM` range;
//! - [`MAX_DEPENDENCY_DEPTH`] cells on the dependency traversal stack.

use std::collections::BTreeMap;

mod formula;
mod package;

pub use formula::Address;
pub use package::{
    budget_package, run_table_arithmetic, BUDGET_FAMILY, BUDGET_KIND, BUDGET_NAME,
    BUDGET_NAMESPACE, BUDGET_SOURCE_FIELD, RECALCULATE_OPERATION, SHEET_DEFINITION,
};

/// Maximum number of cells (distinct normalised addresses) in one sheet.
pub const MAX_CELLS: usize = 256;
/// Maximum bytes in one cell's expression (the raw input value, after
/// trimming). ASCII and multi-byte characters both count their UTF-8 bytes.
pub const MAX_FORMULA_BYTES: usize = 1024;
/// Maximum total expression bytes across the whole sheet (64 KiB).
pub const MAX_TOTAL_EXPRESSION_BYTES: usize = 64 * 1024;
/// Maximum parser nesting depth (parentheses and stacked unary operators).
pub const MAX_NESTING_DEPTH: usize = 32;
/// Maximum number of lexed tokens in one expression.
pub const MAX_TOKENS_PER_EXPRESSION: usize = 256;
/// Maximum number of cells a single `SUM` range may cover.
pub const MAX_RANGE_MEMBERS: usize = 256;
/// Maximum number of cells on the dependency traversal stack.
pub const MAX_DEPENDENCY_DEPTH: usize = 32;

/// A named refusal or evaluation failure.
///
/// Every variant is a distinct, stable reason. Caps are refused at admission;
/// the evaluation variants are deterministic because the sheet is visited in a
/// fixed order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetError {
    /// More than [`MAX_CELLS`] distinct addresses were supplied.
    TooManyCells { count: usize, max: usize },
    /// One cell expression exceeded [`MAX_FORMULA_BYTES`].
    FormulaTooLong {
        address: String,
        bytes: usize,
        max: usize,
    },
    /// The summed expression bytes exceeded [`MAX_TOTAL_EXPRESSION_BYTES`].
    ExpressionsTooLarge { bytes: usize, max: usize },
    /// An input key, or a token in a formula, is not a valid `A1`-`Z99`
    /// address.
    InvalidAddress { raw: String },
    /// Two input keys normalised to the same address.
    DuplicateAddress { address: String },
    /// The expression could not be parsed.
    MalformedSyntax { address: String, detail: String },
    /// An expression lexed to more than [`MAX_TOKENS_PER_EXPRESSION`] tokens.
    TooManyTokens {
        address: String,
        count: usize,
        max: usize,
    },
    /// A cell's expression nested deeper than [`MAX_NESTING_DEPTH`].
    NestingTooDeep {
        address: String,
        depth: usize,
        max: usize,
    },
    /// A `SUM` range covered more than [`MAX_RANGE_MEMBERS`] cells.
    RangeTooLarge {
        address: String,
        members: usize,
        max: usize,
    },
    /// A referenced address is absent from the input map.
    MissingReference { address: String, referenced: String },
    /// The dependency traversal found a cycle. `chain` repeats the closing
    /// address, so `A1 -> B1 -> A1` is `["A1", "B1", "A1"]`.
    Cycle { chain: Vec<String> },
    /// The dependency chain exceeded [`MAX_DEPENDENCY_DEPTH`].
    DependencyTooDeep { chain: Vec<String>, max: usize },
    /// A division by an exact zero denominator.
    DivisionByZero { address: String },
    /// A literal or a computed value was `inf` or `NaN`.
    NonFiniteResult { address: String },
}

impl std::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BudgetError::TooManyCells { count, max } => {
                write!(f, "sheet has {count} cells, over the cap of {max}")
            }
            BudgetError::FormulaTooLong {
                address,
                bytes,
                max,
            } => write!(
                f,
                "cell {address} expression is {bytes} bytes, over the cap of {max}"
            ),
            BudgetError::ExpressionsTooLarge { bytes, max } => write!(
                f,
                "sheet expressions total {bytes} bytes, over the cap of {max}"
            ),
            BudgetError::InvalidAddress { raw } => {
                write!(f, "invalid cell address {raw:?}")
            }
            BudgetError::DuplicateAddress { address } => {
                write!(f, "duplicate cell address {address}")
            }
            BudgetError::MalformedSyntax { address, detail } => {
                write!(f, "malformed formula in cell {address}: {detail}")
            }
            BudgetError::TooManyTokens {
                address,
                count,
                max,
            } => write!(
                f,
                "cell {address} lexed {count} tokens, over the cap of {max}"
            ),
            BudgetError::NestingTooDeep {
                address,
                depth,
                max,
            } => write!(
                f,
                "cell {address} nested to depth {depth}, over the cap of {max}"
            ),
            BudgetError::RangeTooLarge {
                address,
                members,
                max,
            } => write!(
                f,
                "cell {address} SUM range covers {members} cells, over the cap of {max}"
            ),
            BudgetError::MissingReference {
                address,
                referenced,
            } => write!(f, "cell {address} references absent cell {referenced}"),
            BudgetError::Cycle { chain } => {
                write!(f, "dependency cycle: {}", chain.join(" -> "))
            }
            BudgetError::DependencyTooDeep { chain, max } => write!(
                f,
                "dependency chain of {} cells exceeds the cap of {max}: {}",
                chain.len(),
                chain.join(" -> ")
            ),
            BudgetError::DivisionByZero { address } => {
                write!(f, "division by zero in cell {address}")
            }
            BudgetError::NonFiniteResult { address } => {
                write!(f, "cell {address} produced a non-finite result")
            }
        }
    }
}

impl std::error::Error for BudgetError {}

/// A successfully evaluated sheet.
///
/// Values are keyed by normalised [`Address`]. The map is row-major ordered
/// because [`Address`] is.
#[derive(Debug, Clone, PartialEq)]
pub struct Evaluated {
    values: BTreeMap<Address, f64>,
}

impl Evaluated {
    /// Look up a cell by its canonical or lowercase address spelling.
    pub fn get(&self, address: &str) -> Option<f64> {
        Address::parse(address).and_then(|address| self.values.get(&address).copied())
    }

    /// The full address-to-value map, row-major ordered.
    pub fn values(&self) -> &BTreeMap<Address, f64> {
        &self.values
    }

    /// Consume the sheet and return its map.
    pub fn into_values(self) -> BTreeMap<Address, f64> {
        self.values
    }
}

/// Admit and evaluate a whole sheet.
///
/// `cells` yields `(address, expression)` pairs. Addresses may be given in any
/// case; they are normalised before duplicate detection. The whole sheet is
/// admitted (addresses normalised, caps checked, and every expression parsed)
/// before any arithmetic is evaluated, so a malformed or oversized cell is
/// refused without evaluating its neighbours.
pub fn evaluate<I, K, V>(cells: I) -> Result<Evaluated, BudgetError>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    // Admission is bounded: at most MAX_CELLS+1 entries are materialised, so a
    // hostile iterator yielding millions of cells costs one extra copy, not an
    // unbounded allocation. `count` in the refusal is the first count over the
    // cap (MAX_CELLS+1), not the true total. This cap is checked before address
    // normalisation, so an oversized sheet is refused before any per-cell work.
    let mut entries: Vec<(String, String)> = Vec::new();
    let mut iter = cells.into_iter();
    while entries.len() <= MAX_CELLS {
        match iter.next() {
            Some((key, value)) => {
                entries.push((key.as_ref().to_string(), value.as_ref().to_string()));
            }
            None => break,
        }
    }
    if entries.len() > MAX_CELLS {
        return Err(BudgetError::TooManyCells {
            count: entries.len(),
            max: MAX_CELLS,
        });
    }

    // Sort by the raw key so error selection is independent of the caller's
    // iteration order.
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    // Admission: normalise addresses and detect duplicates.
    let mut raw: BTreeMap<Address, String> = BTreeMap::new();
    for (key, value) in entries {
        let address = Address::parse(key.trim())
            .ok_or_else(|| BudgetError::InvalidAddress { raw: key.clone() })?;
        if raw.contains_key(&address) {
            return Err(BudgetError::DuplicateAddress {
                address: address.to_string(),
            });
        }
        raw.insert(address, value);
    }

    // Admission: per-expression and aggregate byte caps (before parsing).
    let mut total_bytes = 0usize;
    for (address, value) in &raw {
        if value.len() > MAX_FORMULA_BYTES {
            return Err(BudgetError::FormulaTooLong {
                address: address.to_string(),
                bytes: value.len(),
                max: MAX_FORMULA_BYTES,
            });
        }
        total_bytes += value.len();
    }
    if total_bytes > MAX_TOTAL_EXPRESSION_BYTES {
        return Err(BudgetError::ExpressionsTooLarge {
            bytes: total_bytes,
            max: MAX_TOTAL_EXPRESSION_BYTES,
        });
    }

    // Admission: parse every expression before evaluating any of them.
    let mut parsed: BTreeMap<Address, formula::Expr> = BTreeMap::new();
    for (address, value) in &raw {
        parsed.insert(*address, parse_cell(address, value)?);
    }

    evaluate_parsed(&parsed)
}

fn parse_cell(address: &Address, value: &str) -> Result<formula::Expr, BudgetError> {
    let trimmed = value.trim();
    let body = trimmed.strip_prefix('=').unwrap_or(trimmed);
    formula::parse(body).map_err(|error| map_parse_error(address, error))
}

fn map_parse_error(address: &Address, error: formula::ParseError) -> BudgetError {
    use formula::ParseError as E;
    match error {
        E::Empty => malformed(address, "empty expression"),
        E::UnexpectedChar(c) => malformed(address, format!("unexpected character '{c}'")),
        E::UnknownIdentifier(name) => malformed(address, format!("unknown identifier '{name}'")),
        E::InvalidAddress(raw) => BudgetError::InvalidAddress { raw },
        E::MalformedNumber(raw) => malformed(address, format!("malformed number '{raw}'")),
        E::NonFinite => BudgetError::NonFiniteResult {
            address: address.to_string(),
        },
        E::TooManyTokens { count, max } => BudgetError::TooManyTokens {
            address: address.to_string(),
            count,
            max,
        },
        E::NestingTooDeep { depth, max } => BudgetError::NestingTooDeep {
            address: address.to_string(),
            depth,
            max,
        },
        E::RangeTooLarge { members, max } => BudgetError::RangeTooLarge {
            address: address.to_string(),
            members,
            max,
        },
        E::ExpectedExpression => malformed(address, "expected an expression"),
        E::ExpectedToken(what) => malformed(address, format!("expected {what}")),
        E::UnexpectedEnd => malformed(address, "unexpected end of expression"),
        E::TrailingInput => malformed(address, "unexpected trailing input"),
    }
}

fn malformed(address: &Address, detail: impl Into<String>) -> BudgetError {
    BudgetError::MalformedSyntax {
        address: address.to_string(),
        detail: detail.into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Visit {
    InProgress,
    Done,
}

struct Evaluator<'a> {
    cells: &'a BTreeMap<Address, formula::Expr>,
    values: BTreeMap<Address, f64>,
    state: BTreeMap<Address, Visit>,
    stack: Vec<Address>,
}

impl<'a> Evaluator<'a> {
    fn new(cells: &'a BTreeMap<Address, formula::Expr>) -> Evaluator<'a> {
        Evaluator {
            cells,
            values: BTreeMap::new(),
            state: BTreeMap::new(),
            stack: Vec::new(),
        }
    }

    /// Memoised, cycle-checked value of `target`, referenced from `current`.
    fn value_of(&mut self, target: Address, current: Address) -> Result<f64, BudgetError> {
        if let Some(value) = self.values.get(&target) {
            return Ok(*value);
        }
        if self.state.get(&target) == Some(&Visit::InProgress) {
            let start = self
                .stack
                .iter()
                .position(|address| *address == target)
                .unwrap_or(0);
            let mut chain = self.stack[start..].to_vec();
            chain.push(target);
            return Err(BudgetError::Cycle {
                chain: chain.iter().map(|address| address.to_string()).collect(),
            });
        }
        if self.stack.len() >= MAX_DEPENDENCY_DEPTH {
            return Err(BudgetError::DependencyTooDeep {
                chain: self
                    .stack
                    .iter()
                    .map(|address| address.to_string())
                    .collect(),
                max: MAX_DEPENDENCY_DEPTH,
            });
        }
        let expr =
            self.cells
                .get(&target)
                .cloned()
                .ok_or_else(|| BudgetError::MissingReference {
                    address: current.to_string(),
                    referenced: target.to_string(),
                })?;

        self.state.insert(target, Visit::InProgress);
        self.stack.push(target);
        let value = self.eval_expr(&expr, target)?;
        self.stack.pop();
        self.state.insert(target, Visit::Done);

        if !value.is_finite() {
            return Err(BudgetError::NonFiniteResult {
                address: target.to_string(),
            });
        }
        self.values.insert(target, value);
        Ok(value)
    }

    /// Reject a non-finite intermediate or result. Finite-only arithmetic
    /// keeps an overflowed subexpression from silently collapsing to `0`
    /// through `1 / inf` or `inf - inf`: the first non-finite value is a named
    /// error attributed to the cell being evaluated.
    fn finite(value: f64, current: Address) -> Result<f64, BudgetError> {
        if value.is_finite() {
            Ok(value)
        } else {
            Err(BudgetError::NonFiniteResult {
                address: current.to_string(),
            })
        }
    }

    fn eval_expr(&mut self, expr: &formula::Expr, current: Address) -> Result<f64, BudgetError> {
        match expr {
            formula::Expr::Number(value) => Ok(*value),
            formula::Expr::Cell(target) => self.value_of(*target, current),
            formula::Expr::Neg(inner) => {
                let inner = self.eval_expr(inner, current)?;
                Self::finite(-inner, current)
            }
            formula::Expr::Add(lhs, rhs) => {
                let lhs = self.eval_expr(lhs, current)?;
                let rhs = self.eval_expr(rhs, current)?;
                Self::finite(lhs + rhs, current)
            }
            formula::Expr::Sub(lhs, rhs) => {
                let lhs = self.eval_expr(lhs, current)?;
                let rhs = self.eval_expr(rhs, current)?;
                Self::finite(lhs - rhs, current)
            }
            formula::Expr::Mul(lhs, rhs) => {
                let lhs = self.eval_expr(lhs, current)?;
                let rhs = self.eval_expr(rhs, current)?;
                Self::finite(lhs * rhs, current)
            }
            formula::Expr::Div(lhs, rhs) => {
                let lhs = self.eval_expr(lhs, current)?;
                let rhs = self.eval_expr(rhs, current)?;
                if rhs == 0.0 {
                    return Err(BudgetError::DivisionByZero {
                        address: current.to_string(),
                    });
                }
                Self::finite(lhs / rhs, current)
            }
            formula::Expr::Sum(range) => {
                let mut total = 0.0;
                for member in range.cells() {
                    total = Self::finite(total + self.value_of(member, current)?, current)?;
                }
                Ok(total)
            }
        }
    }
}

fn evaluate_parsed(cells: &BTreeMap<Address, formula::Expr>) -> Result<Evaluated, BudgetError> {
    let mut evaluator = Evaluator::new(cells);
    for address in cells.keys() {
        evaluator.value_of(*address, *address)?;
    }
    Ok(Evaluated {
        values: evaluator.values,
    })
}

#[cfg(test)]
mod tests;
