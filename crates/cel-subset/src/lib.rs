//! # CEL-Rust
//!
//! A parser and interpreter for the Common Expression Language (CEL) in Rust.
//!
//! ## Optional Features
//!
//! - `structs`: Enables support for custom struct types. This allows you to define
//!   struct definitions using [`StructDef`] and add them to your [`Env`].
//!   Custom structs can then be instantiated and accessed within CEL expressions.
//! - `chrono`: Enables support for `duration` and `timestamp` types using the `chrono` crate.
//! - `regex`: Enables support for regular expressions.
//! - `json`: Enables conversion between CEL values and JSON.
//!
extern crate core;

use std::convert::TryFrom;
use std::sync::Arc;
use thiserror::Error;

mod macros;

// Locked-down surface (design §7.2 item 2): only `check` and
// `evaluate`, plus `Policy` and the outcome/report types, are
// public. Every other module is crate-private; `IdedExpr` stays
// re-exported only because `ExecutionError` variants name it.
pub mod api;
mod charges;
mod common;
mod comprehension;
mod context;
#[cfg(test)]
mod copy_tests;
mod env;
mod estimate;
mod extrema;
mod guard;
mod input;
mod limits;
mod load;
mod meter;
mod metrics;
#[cfg(any(test, feature = "native-proof-tools"))]
#[allow(dead_code)] // private cap-agnostic data, intentionally richer than each harness
mod native_fixture_sets;
#[cfg(any(test, feature = "native-proof-tools"))]
#[allow(dead_code)]
mod native_measure;
#[cfg(any(test, feature = "native-proof-tools"))]
#[allow(dead_code)]
mod native_proof_harness;
#[cfg(any(test, feature = "native-proof-tools"))]
mod native_regex_measure;
#[cfg(any(test, feature = "native-proof-tools"))]
#[allow(dead_code)]
mod native_rule_generator;
/// Native evidence tool entry point; available only with the explicit tooling
/// feature. It accepts named measurement candidates, never caller policy values.
#[cfg(feature = "native-proof-tools")]
#[doc(hidden)]
pub fn native_evidence(mode: &str, candidate: usize, count: usize) -> Result<String, String> {
    native_measure::run(mode, candidate, count)
        .and_then(|report| serde_json::to_string_pretty(&report).map_err(|e| e.to_string()))
}
mod quantity;
mod rule;
pub use input::{Declarations, InputDecl, InputKind, ScalarType};
mod parser;
mod policy;

#[cfg(not(test))]
pub use api::check;
#[cfg(test)]
pub(crate) use api::legacy_check as check;
pub use api::{evaluate, Bindings, CheckReport, EvalCost, EvalReport, ParseCaps, Prepared};
pub use estimate::Bound;
pub use guard::{check_guard, guard, GuardCheckReport, GuardReport, PreparedGuard};
pub use limits::Measures;
pub use policy::Policy;
pub use rule::{
    check_rule, evaluate_rule, CheckedRuleBindings, Clause, ClausePhase, GuardSource,
    PrefixProgress, PreparedRule, RuleCheckError, RuleCheckReport, RuleDecision, RuleError,
    RuleEvalReport, RulePrefix,
};

pub use common::ast::IdedExpr;
use common::ast::SelectExpr;
// Crate-visible aliases for the pre-lockdown root paths, so vendored
// modules keep compiling unchanged while exporting nothing new.
pub(crate) use context::Context;
pub(crate) use env::Env;
use functions::FunctionContext;
use objects::ResolveResult;
pub use objects::Value;
use parser::{Expression, Parser};
pub use parser::{ParseError, ParseErrors};
#[cfg(test)]
mod corpus_tests;
mod functions;
mod magic;
mod objects;
#[cfg(test)]
mod parse_proof_tests;
mod regexes;
mod resolvers;
mod subset;
mod symbolic_control;
#[cfg(test)]
mod u3_alloc_tests;
mod val_desc;

pub use val_desc::ValueDesc;

mod duration;

mod ser;

#[cfg(feature = "json")]
mod json;

use magic::FromContext;

#[derive(Error, Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum ExecutionError {
    #[error("Invalid argument count: expected {expected}, got {actual}")]
    InvalidArgumentCount { expected: usize, actual: usize },
    #[error("Invalid argument type: {:?}", .target)]
    UnsupportedTargetType { target: ValueDesc },
    #[error("Method '{method}' not supported on type '{target:?}'")]
    NotSupportedAsMethod { method: String, target: ValueDesc },
    /// Indicates that the script attempted to use a value as a key in a map,
    /// but the type of the value was not supported as a key.
    #[error("Unable to use value '{0:?}' as a key")]
    UnsupportedKeyType(ValueDesc),
    #[error("Unexpected type: got '{got}', want '{want}'")]
    UnexpectedType { got: String, want: String },
    /// Indicates that the script attempted to reference a key on a type that
    /// was missing the requested key.
    #[error("No such key: {0}")]
    NoSuchKey(Arc<String>),
    /// Indicates that the script used an existing operator or function with
    /// values of one or more types for which no overload was declared.
    #[error("No such overload")]
    NoSuchOverload,
    /// Indicates that the script attempted to reference an undeclared variable
    /// method, or function.
    #[error("Undeclared reference to '{0}'")]
    UndeclaredReference(Arc<String>),
    /// Indicates that a function expected to be called as a method, or to be
    /// called with at least one parameter.
    #[error("Missing argument or target")]
    MissingArgumentOrTarget,
    /// Indicates that a comparison could not be performed.
    #[error("{0:?} can not be compared to {1:?}")]
    ValuesNotComparable(ValueDesc, ValueDesc),
    #[deprecated]
    #[error("Unsupported unary operator '{0}': {1:?}")]
    UnsupportedUnaryOperator(&'static str, ValueDesc),
    /// Indicates that an unsupported binary operator was applied on two values
    /// where it's unsupported, for example list + map.
    #[error("Unsupported binary operator '{0}': {1:?}, {2:?}")]
    UnsupportedBinaryOperator(&'static str, ValueDesc, ValueDesc),
    #[deprecated]
    #[error("Cannot use value as map index: {0:?}")]
    UnsupportedMapIndex(ValueDesc),
    #[deprecated]
    #[error("Cannot use value as list index: {0:?}")]
    UnsupportedListIndex(ValueDesc),
    /// Indicates that an unsupported type was used to index a list
    #[error("Cannot use value {0:?} to index {1:?}")]
    UnsupportedIndex(ValueDesc, ValueDesc),
    #[deprecated]
    #[error("Unsupported function call identifier type: {0:?}")]
    UnsupportedFunctionCallIdentifierType(Expression),
    #[deprecated]
    #[error("Unsupported fields construction: {0:?}")]
    UnsupportedFieldsConstruction(SelectExpr),
    /// Indicates that a function had an error during execution.
    #[error("Error executing function '{function}': {message}")]
    FunctionError { function: String, message: String },
    #[error("Division by zero of {0:?}")]
    DivisionByZero(ValueDesc),
    #[error("Remainder by zero of {0:?}")]
    RemainderByZero(ValueDesc),
    #[error("Overflow from binary operator '{0}': {1:?}, {2:?}")]
    Overflow(&'static str, ValueDesc, ValueDesc),
    /// Indicates that a unary operator overflowed (currently only
    /// unary minus on `int::MIN`). Fork addition: the upstream
    /// `Overflow` variant is binary-shaped, so reusing it would
    /// require a dummy second operand.
    #[error("Overflow from unary operator '{0}': {1:?}")]
    UnaryOverflow(&'static str, ValueDesc),
    #[error("Index out of bounds: {0:?}")]
    IndexOutOfBounds(Value),
    /// The rule needs more computation than the policy's work budget
    /// allows (design §1.4 `work_budget`). Charged before the work,
    /// so a refused operation never ran.
    #[error("{0}")]
    WorkBudgetExceeded(String),
    /// The rule holds more retained data at once than the policy's
    /// memory budget allows (design §1.4 `memory_budget`), measured
    /// as the scoped high-water mark.
    #[error("{0}")]
    MemoryBudgetExceeded(String),
    /// The evaluator depth assertion fired (design §1.4
    /// `internal_limit`). Not a budget: an engine defect, reported
    /// "couldn't evaluate", never a verdict.
    #[error("{0}")]
    InternalLimit(String),
    /// A `Prepared` rule was evaluated under a different policy than
    /// the one it was checked under (review F5). A caller error, not
    /// an engine defect: the compiled `matches` tiers are baked from
    /// the check policy.
    #[error("{0}")]
    PolicyMismatch(String),
    #[error("input_refused: {cap} at {path}: {measured} exceeds/violates {limit}; {message}")]
    InputRefused {
        cap: String,
        path: String,
        measured: u64,
        limit: u64,
        message: String,
    },
    #[error("InternalError: {0:?}")]
    InternalError(String),
}

impl ExecutionError {
    pub fn no_such_key(name: &str) -> Self {
        ExecutionError::NoSuchKey(Arc::new(name.to_string()))
    }

    pub fn undeclared_reference(name: &str) -> Self {
        ExecutionError::UndeclaredReference(Arc::new(name.to_string()))
    }

    pub fn invalid_argument_count(expected: usize, actual: usize) -> Self {
        ExecutionError::InvalidArgumentCount { expected, actual }
    }

    pub(crate) fn unexpected_type(got: &str, want: &str) -> Self {
        if let Err(refusal) = meter::charge_cost(charges::diagnostic()) {
            return refusal;
        }
        meter::note_op_body();
        fn text(s: &str) -> String {
            let mut end = s.len().min(128);
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            s[..end].to_string()
        }
        ExecutionError::UnexpectedType {
            got: text(got),
            want: text(want),
        }
    }

    pub fn function_error<E: std::fmt::Display>(function: &str, error: E) -> Self {
        if let Err(refusal) = meter::charge_cost(charges::diagnostic()) {
            return refusal;
        }
        meter::note_op_body();
        // All admitted callers supply bounded fixed parser messages. The writer
        // additionally caps rendering before allocation for private test callers.
        struct Text(String);
        impl std::fmt::Write for Text {
            fn write_str(&mut self, s: &str) -> std::fmt::Result {
                let remaining = 128usize.saturating_sub(self.0.len());
                let mut end = s.len().min(remaining);
                while !s.is_char_boundary(end) {
                    end -= 1;
                }
                self.0.push_str(&s[..end]);
                if end < s.len() {
                    Err(std::fmt::Error)
                } else {
                    Ok(())
                }
            }
        }
        let mut text = Text(String::new());
        let _ = std::fmt::write(&mut text, format_args!("{error}"));
        ExecutionError::FunctionError {
            function: function.chars().take(64).collect(),
            message: text.0,
        }
    }

    pub fn unsupported_target_type(target: impl Into<ValueDesc>) -> Self {
        ExecutionError::UnsupportedTargetType {
            target: target.into(),
        }
    }

    pub fn not_supported_as_method(method: &str, target: impl Into<ValueDesc>) -> Self {
        ExecutionError::NotSupportedAsMethod {
            method: method.to_string(),
            target: target.into(),
        }
    }

    pub fn unsupported_key_type(value: impl Into<ValueDesc>) -> Self {
        ExecutionError::UnsupportedKeyType(value.into())
    }

    pub fn missing_argument_or_target() -> Self {
        ExecutionError::MissingArgumentOrTarget
    }
}

/// Stack size for [`Program::execute_on_stack`]: carries every
/// shape the parse size policy admits (depth 32 of each kind,
/// 256-token chains) in BOTH debug and release.
pub(crate) const STACK_8MIB: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct Program {
    expression: Expression,
    source_info: Arc<crate::common::ast::SourceInfo>,
}

impl Program {
    pub(crate) fn compile(source: &str) -> Result<Program, ParseErrors> {
        let parser = Parser::default();
        parser
            .parse_with_source_info(source)
            .map(|(expression, source_info)| Program {
                expression,
                source_info,
            })
    }

    /// Unbudgeted evaluation, kept only for crate-internal tests.
    #[cfg(test)]
    pub(crate) fn execute(&self, context: &Context) -> ResolveResult {
        Value::resolve(&self.expression, context)
    }

    /// Evaluate with a [`meter::Budget`] (fork addition): installs the
    /// budget for the current thread, evaluates, and returns the
    /// result with the [`charges::Cost`] consumed (cumulative work and
    /// the memory high-water mark). Breaching a meter yields a typed
    /// `WorkBudgetExceeded` / `MemoryBudgetExceeded` (or
    /// `InternalLimit` for the depth assertion). Panic-safe: the
    /// previous setting is restored by a guard even if evaluation
    /// unwinds, and the cost is read before that guard runs.
    pub(crate) fn execute_budgeted(
        &self,
        context: &Context,
        budget: meter::Budget,
    ) -> (ResolveResult, charges::Cost) {
        struct Restore(Option<meter::Budget>);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = meter::clear();
                if let Some(prev) = self.0 {
                    let _ = meter::install(prev);
                }
            }
        }
        let prev = meter::install(budget);
        let _restore = Restore(prev);
        let result = Value::resolve(&self.expression, context);
        let cost = meter::totals().unwrap_or(charges::Cost::ZERO);
        // F2: a latched budget refusal wins over whatever value the
        // absorption sites computed.
        if let Some(err) = meter::tripped() {
            return (Err(err), cost);
        }
        (result, cost)
    }

    /// Returns the contained expression (crate-visible only).
    pub(crate) fn expression(&self) -> &Expression {
        &self.expression
    }
    pub(crate) fn source_info(&self) -> &Arc<crate::common::ast::SourceInfo> {
        &self.source_info
    }
}

impl TryFrom<&str> for Program {
    type Error = ParseErrors;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Program::compile(value)
    }
}

#[cfg(test)]
mod tests {
    use crate::context::Context;
    use crate::objects::{ResolveResult, Value};
    use crate::{ExecutionError, Program};
    use std::convert::TryInto;

    /// Tests the provided script and returns the result. An optional context can be provided.
    pub(crate) fn test_script(script: &str, ctx: Option<Context>) -> ResolveResult {
        let program = match Program::compile(script) {
            Ok(p) => p,
            Err(e) => panic!("{}", e),
        };
        program.execute(&ctx.unwrap_or_default())
    }

    #[test]
    fn parse() {
        Program::compile("1 + 1").unwrap();
    }

    #[test]
    fn from_str() {
        let input = "1.1";
        let _p: Program = input.try_into().unwrap();
    }

    #[test]
    fn variables() {
        fn assert_output(script: &str, expected: ResolveResult) {
            let mut ctx = Context::default();
            ctx.add_variable_from_value("foo", indexmap::IndexMap::from([("bar", 1i64)]));
            ctx.add_variable_from_value("arr", vec![1i64, 2, 3]);
            ctx.add_variable_from_value("str", "foobar".to_string());
            assert_eq!(test_script(script, Some(ctx)), expected);
        }

        // Test methods
        assert_output("size([1, 2, 3]) == 3", Ok(true.into()));
        assert_output("size([size([42]), 2, 3]) == 3", Ok(true.into()));
        assert_output("size([]) == 3", Ok(false.into()));

        // Test variable attribute traversals
        assert_output("foo.bar == 1", Ok(true.into()));

        // Test that we can index into an array
        assert_output("arr[0] == 1", Ok(true.into()));

        // Test that we cannot index into a string
        assert_output("str[0]", Err(ExecutionError::NoSuchOverload));
    }

    #[test]
    fn references() {
        let p = Program::compile("[1, 1].map(x, x * 2)").unwrap();
        assert!(p.expression().references().has_variable("x"));
        assert_eq!(p.expression().references().variables().len(), 1);
    }

    #[test]
    fn test_execution_errors() {
        let tests = vec![
            (
                "no such key",
                "foo.baz.bar == 1",
                ExecutionError::no_such_key("baz"),
            ),
            (
                "undeclared reference",
                "missing == 1",
                ExecutionError::undeclared_reference("missing"),
            ),
            (
                "undeclared method",
                "1.missing()",
                ExecutionError::undeclared_reference("missing"),
            ),
            (
                "undeclared function",
                "missing(1)",
                ExecutionError::undeclared_reference("missing"),
            ),
            (
                "unsupported key type",
                "{null: true}",
                ExecutionError::unsupported_key_type(Value::Null),
            ),
        ];

        for (name, script, error) in tests {
            let mut ctx = Context::default();
            ctx.add_variable_from_value("foo", indexmap::IndexMap::from([("bar", 1)]));
            let res = test_script(script, Some(ctx));
            assert_eq!(res, error.into(), "{name}");
        }
    }
}
