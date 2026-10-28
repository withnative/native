//! The `demo.budget/sheet@1` package fixture and its trusted host provider.
//!
//! Gated with the rest of `crate::v2_budget`. The package is one ordinary
//! `Budget:sheet` record: `title` plus `cells_json`, a text field carrying a
//! JSON object of grid address -> expression. There are no cell records and no
//! cross-family links.
//!
//! The provider is pure: it consumes only the source text and returns the
//! result envelope. It never touches storage, so the generic operation caller
//! (`crate::package_operations`) remains the only code that reads the record,
//! checks authority, and pins a receipt.

use std::fmt;

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::Deserialize;

use crate::package_manifest::{
    DefinitionEntry, OperationDescriptor, PackageManifest, OPERATION_PROVIDER_HOST_TABLE_ARITHMETIC,
};

use super::{evaluate, Address, BudgetError};

/// Namespace of the first budget package.
pub const BUDGET_NAMESPACE: &str = "demo.budget";
/// Package name.
pub const BUDGET_NAME: &str = "sheet";
/// Definition family of the sheet kind.
pub const BUDGET_FAMILY: &str = "demo.budget.sheet";
/// The record kind carrying a budget sheet.
pub const BUDGET_KIND: &str = "sheet";
/// The text field the operation reads and writes.
pub const BUDGET_SOURCE_FIELD: &str = "cells_json";
/// The one operation name.
pub const RECALCULATE_OPERATION: &str = "recalculate";
/// Exact definition bytes (whitespace significant).
pub const SHEET_DEFINITION: &str = include_str!("sheet.defn.json");

/// The `demo.budget/sheet@1` package: one `Budget:sheet` definition plus the
/// `recalculate` operation served by the trusted host provider.
pub fn budget_package() -> PackageManifest {
    let digest =
        crate::meta::definition_artifact::digest_artifact_bytes(SHEET_DEFINITION.as_bytes());
    PackageManifest {
        namespace: BUDGET_NAMESPACE.to_string(),
        name: BUDGET_NAME.to_string(),
        version: 1,
        definitions: vec![DefinitionEntry {
            family: BUDGET_FAMILY.to_string(),
            version: 1,
            artifact_bytes: SHEET_DEFINITION.to_string(),
            digest,
        }],
        behaviour: None,
        surface: None,
        declared_reads: vec!["record:view".to_string()],
        operations: vec![OperationDescriptor {
            name: RECALCULATE_OPERATION.to_string(),
            description:
                "Evaluate every budget cell from cells_json and return each cell's value, or a named error."
                    .to_string(),
            provider: OPERATION_PROVIDER_HOST_TABLE_ARITHMETIC.to_string(),
            executable: None,
            family: BUDGET_FAMILY.to_string(),
            kind: BUDGET_KIND.to_string(),
            source_field: BUDGET_SOURCE_FIELD.to_string(),
            reads: vec!["record:view".to_string()],
            effects: vec![],
        }],
    }
}

/// Evaluate one budget source text (the value of `cells_json`).
///
/// Always returns a result envelope; a domain failure is reported as a named
/// `error` with whatever source-cell context applies, not as a Rust error, so
/// the generic caller can still return a receipt. The shape is:
///
/// ```json
/// {"cells":{"A1":{"expression":"100","value":100.0,"error":null}}, "error":null}
/// ```
///
/// On failure `cells` is empty and `error` is
/// `{"kind","message","address"?,"referenced"?}`. The result is
/// `serde_json::Value` because this prototype's arithmetic is finite `f64`,
/// not exact currency accounting.
pub fn run_table_arithmetic(source: &str) -> serde_json::Value {
    // Strict duplicate-key parse: `serde_json::Value` silently drops an
    // earlier value for a repeated key, which would let a stored
    // `{"A1":"1","A1":"2"}` slip past the evaluator's duplicate check. This
    // visitor refuses the second occurrence instead.
    let strict: StrictCells = match serde_json::from_str(source) {
        Ok(strict) => strict,
        Err(error) => {
            return failure(
                "InvalidSource",
                format!("cells_json is not valid JSON: {error}"),
                None,
                None,
            )
        }
    };
    let map = strict.0;
    let mut pairs: Vec<(String, String)> = Vec::with_capacity(map.len());
    for (address, value) in &map {
        match value.as_str() {
            Some(expression) => pairs.push((address.clone(), expression.to_string())),
            None => {
                return failure(
                    "InvalidSource",
                    format!("cell {address} must hold a string expression"),
                    Some(address.clone()),
                    None,
                )
            }
        }
    }
    match evaluate(pairs) {
        Ok(evaluated) => {
            let values = evaluated.into_values();
            let mut cells = serde_json::Map::new();
            // Look the value up by canonical address but keep the source
            // expression as written, so a lowercase or leading-zero key
            // (`a01`) still reports the caller's exact text.
            for (raw, expression) in &map {
                let address =
                    Address::parse(raw.trim()).expect("admitted address must parse canonically");
                let value = values.get(&address).copied().unwrap_or(0.0);
                cells.insert(
                    address.to_string(),
                    serde_json::json!({
                        "expression": expression.as_str().unwrap_or_default(),
                        "value": value,
                        "error": serde_json::Value::Null,
                    }),
                );
            }
            serde_json::json!({
                "cells": serde_json::Value::Object(cells),
                "error": serde_json::Value::Null,
            })
        }
        Err(error) => {
            let (kind, message, address, referenced) = describe_error(&error);
            failure(kind, message, address, referenced)
        }
    }
}

/// A JSON object with duplicate keys refused rather than last-wins.
struct StrictCells(serde_json::Map<String, serde_json::Value>);

impl<'de> Deserialize<'de> for StrictCells {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CellsVisitor;

        impl<'de> Visitor<'de> for CellsVisitor {
            type Value = StrictCells;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object of cell address -> expression")
            }

            fn visit_map<M>(self, mut access: M) -> Result<StrictCells, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut map = serde_json::Map::new();
                while let Some(key) = access.next_key::<String>()? {
                    let value: serde_json::Value = access.next_value()?;
                    if map.insert(key.clone(), value).is_some() {
                        return Err(de::Error::custom(format!(
                            "duplicate cell address '{key}' in cells_json"
                        )));
                    }
                }
                Ok(StrictCells(map))
            }
        }

        deserializer.deserialize_map(CellsVisitor)
    }
}

fn failure(
    kind: &str,
    message: String,
    address: Option<String>,
    referenced: Option<String>,
) -> serde_json::Value {
    let mut error = serde_json::Map::new();
    error.insert(
        "kind".to_string(),
        serde_json::Value::String(kind.to_string()),
    );
    error.insert("message".to_string(), serde_json::Value::String(message));
    if let Some(address) = address {
        error.insert("address".to_string(), serde_json::Value::String(address));
    }
    if let Some(referenced) = referenced {
        error.insert(
            "referenced".to_string(),
            serde_json::Value::String(referenced),
        );
    }
    serde_json::json!({
        "cells": serde_json::Value::Object(serde_json::Map::new()),
        "error": serde_json::Value::Object(error),
    })
}

fn describe_error(error: &BudgetError) -> (&'static str, String, Option<String>, Option<String>) {
    match error {
        BudgetError::MissingReference {
            address,
            referenced,
        } => (
            "MissingReference",
            error.to_string(),
            Some(address.clone()),
            Some(referenced.clone()),
        ),
        BudgetError::Cycle { chain } => ("Cycle", error.to_string(), chain.first().cloned(), None),
        BudgetError::DivisionByZero { address } => (
            "DivisionByZero",
            error.to_string(),
            Some(address.clone()),
            None,
        ),
        BudgetError::InvalidAddress { raw } => {
            ("InvalidAddress", error.to_string(), Some(raw.clone()), None)
        }
        BudgetError::DuplicateAddress { address } => (
            "DuplicateAddress",
            error.to_string(),
            Some(address.clone()),
            None,
        ),
        BudgetError::MalformedSyntax { address, .. } => (
            "MalformedSyntax",
            error.to_string(),
            Some(address.clone()),
            None,
        ),
        BudgetError::TooManyTokens { address, .. } => (
            "TooManyTokens",
            error.to_string(),
            Some(address.clone()),
            None,
        ),
        BudgetError::NestingTooDeep { address, .. } => (
            "NestingTooDeep",
            error.to_string(),
            Some(address.clone()),
            None,
        ),
        BudgetError::RangeTooLarge { address, .. } => (
            "RangeTooLarge",
            error.to_string(),
            Some(address.clone()),
            None,
        ),
        BudgetError::FormulaTooLong { address, .. } => (
            "FormulaTooLong",
            error.to_string(),
            Some(address.clone()),
            None,
        ),
        BudgetError::NonFiniteResult { address } => (
            "NonFiniteResult",
            error.to_string(),
            Some(address.clone()),
            None,
        ),
        BudgetError::TooManyCells { .. } => ("TooManyCells", error.to_string(), None, None),
        BudgetError::ExpressionsTooLarge { .. } => {
            ("ExpressionsTooLarge", error.to_string(), None, None)
        }
        BudgetError::DependencyTooDeep { chain, .. } => (
            "DependencyTooDeep",
            error.to_string(),
            chain.first().cloned(),
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_declares_one_recalculate_operation() {
        let manifest = budget_package();
        manifest.validate().expect("fixture manifest is valid");
        assert_eq!(manifest.operations.len(), 1);
        assert_eq!(manifest.operations[0].name, RECALCULATE_OPERATION);
        assert!(manifest.package_digest().is_ok());
    }

    #[test]
    fn provider_evaluates_sheet_source() {
        let result = run_table_arithmetic(r#"{"A1":"100","A2":"250","B1":"=A1+A2"}"#);
        assert_eq!(result["error"], serde_json::Value::Null);
        assert_eq!(result["cells"]["B1"]["value"], serde_json::json!(350.0));
        assert_eq!(result["cells"]["B1"]["expression"], "=A1+A2");
    }

    #[test]
    fn provider_reports_named_domain_errors() {
        let missing = run_table_arithmetic(r#"{"A1":"=B1"}"#);
        assert_eq!(missing["error"]["kind"], "MissingReference");
        assert_eq!(missing["error"]["address"], "A1");
        assert_eq!(missing["error"]["referenced"], "B1");

        let malformed = run_table_arithmetic("not json");
        assert_eq!(malformed["error"]["kind"], "InvalidSource");
    }

    #[test]
    fn provider_rejects_duplicate_json_keys() {
        // A `serde_json::Value` parse would keep only the last value; the
        // strict visitor refuses so a stored duplicate is a named error.
        let result = run_table_arithmetic(r#"{"A1":"1","A1":"2"}"#);
        assert_eq!(result["error"]["kind"], "InvalidSource");
        assert!(result["error"]["message"]
            .as_str()
            .expect("message")
            .contains("duplicate"));
    }

    #[test]
    fn provider_preserves_source_expression_for_normalised_keys() {
        let result = run_table_arithmetic(r#"{"a01":"7"}"#);
        assert_eq!(result["cells"]["A1"]["value"], serde_json::json!(7.0));
        assert_eq!(result["cells"]["A1"]["expression"], "7");
    }

    #[test]
    fn descriptor_refusals_are_fail_closed() {
        let mut unknown_provider = budget_package();
        unknown_provider.operations[0].provider = "host.other/1".to_string();
        assert!(unknown_provider.validate().is_err());

        let mut widened_reads = budget_package();
        widened_reads.operations[0].reads =
            vec!["record:view".to_string(), "record:view".to_string()];
        assert!(widened_reads.validate().is_err());

        let mut effects = budget_package();
        effects.operations[0].effects = vec!["write".to_string()];
        assert!(effects.validate().is_err());

        let mut bad_field = budget_package();
        bad_field.operations[0].source_field = "nope".to_string();
        assert!(bad_field.validate().is_err());

        let mut bad_family = budget_package();
        bad_family.operations[0].family = "demo.budget.other".to_string();
        assert!(bad_family.validate().is_err());

        let mut uncovered_read = budget_package();
        uncovered_read.declared_reads.clear();
        assert!(uncovered_read.validate().is_err());

        let mut duplicate = budget_package();
        let second = duplicate.operations[0].clone();
        duplicate.operations.push(second);
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn operations_are_omitted_from_canonical_value_when_empty() {
        let with_ops = budget_package().canonical_value().expect("valid");
        assert!(with_ops.get("operations").is_some());

        let mut without_ops = budget_package();
        without_ops.operations.clear();
        without_ops.declared_reads.clear();
        let value = without_ops.canonical_value().expect("valid");
        assert!(value.get("operations").is_none());
    }

    #[test]
    fn committed_manifest_fixture_matches_builder() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/prototypes/budget_plugin_manifest.json"
        );
        let committed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("fixture present"))
                .expect("fixture is JSON");
        assert_eq!(
            committed,
            budget_package().canonical_value().expect("valid")
        );
    }
}
