//! Shared PR4a pure scalar/guard bridge and closed v1 storage declarations;
//! no guest adapter, persistence or production activation is supplied here.
#![allow(dead_code)] // Reviewable pure seams await the parent-owned real adapter.
use super::rule_install::{
    self as ri, ParameterSource, RuleCardinality, RuleInputDecl, RuleRevision,
};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn reject(message: impl AsRef<str>) -> Error {
    super::sql_contract::categorized_error(
        super::sql_contract::QuerySqlErrorCategory::InvalidArguments,
        message,
    )
}
fn identifier(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .enumerate()
            .all(|(i, c)| c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()))
    {
        return Err(reject(
            "scalar_rows_v1 binding names must be CEL identifiers of 1..128 bytes",
        ));
    }
    Ok(())
}
/// Exactly the current cel-subset InputKind scalar domain; SQL bytes/nested
/// values are excluded. No authored numeric resource settings.
/// Immutable binding schema version, including rules with zero SQL inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingContractVersion {
    ScalarRowsV1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScalarType {
    Int,
    Double,
    Bool,
    String,
    Any,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScalarField {
    pub name: String,
    pub scalar_type: ScalarType,
    pub nullable: bool,
    /// Parse canonical signed decimal facet text, not REAL value_num or CAST.
    #[serde(default, skip_serializing_if = "is_false")]
    pub canonical_integer_text: bool,
}
fn is_false(value: &bool) -> bool {
    !value
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredWhen {
    pub expression: String,
    /// Scheduling edges only. Guest/native check_guard validates expression
    /// names against the complete strict prefix, not a forged author verdict.
    pub inputs: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "version", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleInputContract {
    ScalarRowsV1 {
        fields: Vec<ScalarField>,
        required_when: Option<RequiredWhen>,
    },
}
impl RuleInputContract {
    pub fn fields(&self) -> &[ScalarField] {
        let Self::ScalarRowsV1 { fields, .. } = self;
        fields
    }
    pub fn required_when(&self) -> Option<&RequiredWhen> {
        let Self::ScalarRowsV1 { required_when, .. } = self;
        required_when.as_ref()
    }
    pub fn canonical_value(&self) -> Value {
        let mut copy = self.clone();
        let Self::ScalarRowsV1 {
            fields,
            required_when,
        } = &mut copy;
        fields.sort_by(|a, b| a.name.cmp(&b.name));
        if let Some(guard) = required_when {
            guard.inputs.sort();
        }
        serde_json::to_value(copy).expect("scalar contract")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionFact {
    CompletionTransition,
    SummaryPresent,
    SummaryChangedInWrite,
    SummaryChangedSinceActive,
    ClaimHeld,
    WriterHoldsClaim,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScalarSource {
    Argument,
    NowMs,
    CompletionV1 { fact: CompletionFact },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScalarArgument {
    pub name: String,
    pub scalar_type: ScalarType,
    pub nullable: bool,
    pub source: ScalarSource,
}

pub fn validate_contract(revision: &RuleRevision) -> Result<()> {
    let count = revision
        .inputs
        .iter()
        .filter(|i| i.contract.is_some())
        .count();
    if revision.binding_contract.is_none() {
        if count != 0 || !revision.scalar_arguments.is_empty() {
            return Err(reject(
                "new input/scalar declarations require binding_contract scalar_rows_v1",
            ));
        }
        return Ok(());
    }
    if count != revision.inputs.len() || revision.language != "cel-subset@1" {
        return Err(reject("scalar_rows_v1 requires cel-subset@1 and a contract on every input; do not mix legacy declarations"));
    }
    let mut bindings = BTreeSet::new();
    for input in &revision.inputs {
        identifier(&input.name)?;
        if !bindings.insert(input.name.as_str()) {
            return Err(reject("input binding names must be unique"));
        }
        let contract = input.contract.as_ref().expect("all contracts");
        let mut fields = BTreeSet::new();
        for field in contract.fields() {
            if field.name.is_empty() || !fields.insert(field.name.as_str()) {
                return Err(reject("output field names must be nonempty and unique"));
            }
            if field.canonical_integer_text && field.scalar_type != ScalarType::Int {
                return Err(reject(
                    "canonical integer text conversion needs an int field",
                ));
            }
        }
        let mut required = BTreeSet::new();
        for field in &input.required_fields {
            if !fields.contains(field.as_str()) || !required.insert(field) {
                return Err(reject(
                    "required fields must be unique declared scalar output fields",
                ));
            }
        }
        if let Some(guard) = contract.required_when() {
            if input.cardinality != RuleCardinality::One || guard.expression.is_empty() {
                return Err(reject(
                    "required_when needs a nonempty expression on a One input",
                ));
            }
            let mut dependencies = BTreeSet::new();
            for dep in &guard.inputs {
                identifier(dep)?;
                if !dependencies.insert(dep) {
                    return Err(reject("required_when dependencies must be unique"));
                }
            }
        }
    }
    for scalar in &revision.scalar_arguments {
        identifier(&scalar.name)?;
        if !bindings.insert(&scalar.name) {
            return Err(reject("input and scalar binding names must be distinct"));
        }
        match scalar.source {
            ScalarSource::NowMs if scalar.scalar_type != ScalarType::Int || scalar.nullable => {
                return Err(reject("now_ms is a nonnullable int scalar"))
            }
            ScalarSource::CompletionV1 { .. }
                if scalar.scalar_type != ScalarType::Bool || !scalar.nullable =>
            {
                return Err(reject(
                    "completion facts are nullable bool scalars; null is unknown",
                ))
            }
            _ => {}
        }
    }
    for input in &revision.inputs {
        for parameter in &input.parameters {
            let expected = match parameter.param_type.as_str() {
                "boolean" => ScalarType::Bool, "integer" => ScalarType::Int,
                "real" => ScalarType::Double, "text" => ScalarType::String,
                _ => return Err(reject("scalar_rows_v1 SQL parameters support boolean/integer/real/text; use explicit integer UTC millis, not timestamp/bytes/json coercion")),
            };
            match &parameter.source {
                ParameterSource::Argument { name } => {
                    let scalar = revision
                        .scalar_arguments
                        .iter()
                        .find(|s| &s.name == name)
                        .ok_or_else(|| {
                            reject("SQL argument must have an explicit scalar declaration")
                        })?;
                    if scalar.scalar_type != expected
                        || scalar.nullable != parameter.nullable
                        || scalar.source != ScalarSource::Argument
                    {
                        return Err(reject("SQL argument type/nullability/source must match its scalar declaration"));
                    }
                }
                ParameterSource::NowMs if expected != ScalarType::Int || parameter.nullable => {
                    return Err(reject(
                        "SQL now_ms source requires nonnullable integer parameter",
                    ))
                }
                ParameterSource::InputRow {
                    input: source,
                    field,
                } => {
                    let source = revision
                        .inputs
                        .iter()
                        .find(|i| &i.name == source)
                        .ok_or_else(|| reject("unknown row parameter source"))?;
                    let decl = source
                        .contract
                        .as_ref()
                        .and_then(|c| c.fields().iter().find(|f| &f.name == field))
                        .ok_or_else(|| {
                            reject("row parameter needs a declared scalar source field")
                        })?;
                    if decl.scalar_type != expected || decl.nullable != parameter.nullable {
                        return Err(reject(
                            "row parameter type/nullability must match source field",
                        ));
                    }
                }
                _ => {}
            }
        }
    }
    ri::derive_input_order(revision)?;
    Ok(())
}
/// Verify labels even when execution returns zero rows. Prepared labels are
/// host observations; never author claims. Types are checked on actual cells.
pub fn validate_output_labels(input: &RuleInputDecl, labels: &[String]) -> Result<()> {
    let Some(contract) = &input.contract else {
        return Ok(());
    };
    let actual: BTreeSet<_> = labels.iter().map(String::as_str).collect();
    let declared: BTreeSet<_> = contract.fields().iter().map(|f| f.name.as_str()).collect();
    if actual.len() != labels.len()
        || declared.len() != contract.fields().len()
        || actual != declared
    {
        return Err(reject(
            "SQL labels must exactly match scalar_rows_v1 fields, without duplicate labels",
        ));
    }
    Ok(())
}
fn cell(value: &Value, field: &ScalarField) -> Result<Value> {
    if value.is_null() {
        return if field.nullable {
            Ok(Value::Null)
        } else {
            Err(reject(format!(
                "field '{}' is null but nonnullable",
                field.name
            )))
        };
    }
    if field.canonical_integer_text {
        let text = value.as_str().ok_or_else(|| reject("canonical integer field needs facet_values.value text; never value_num or SQL CAST"))?;
        let integer: i64 = text.parse().map_err(|_| reject("integer facet must be canonical signed decimal text, without fractions or exponent"))?;
        if integer.to_string() != text {
            return Err(reject("integer facet must be canonical signed decimal text (no leading zero, +, whitespace or -0)"));
        }
        let value = Value::from(integer);
        ri::check_safe_numbers(&value)?;
        return Ok(value);
    }
    ri::check_safe_numbers(value)?;
    let matches = match field.scalar_type {
        ScalarType::Int => value.as_i64().is_some(),
        ScalarType::Double => value.is_number(),
        ScalarType::Bool => value.is_boolean() || value.as_i64().is_some_and(|n| n == 0 || n == 1),
        ScalarType::String => value.is_string(),
        ScalarType::Any => value.is_boolean() || value.is_number() || value.is_string(),
    };
    if !matches {
        return Err(reject(format!(
            "field '{}' needs declared scalar {:?}; collections, bytes and coercions refused",
            field.name, field.scalar_type
        )));
    }
    if field.scalar_type == ScalarType::Bool && !value.is_boolean() {
        return Ok(Value::Bool(value.as_i64() == Some(1)));
    }
    if field.scalar_type == ScalarType::Double {
        // All integers have already passed the interoperable ±(2^53-1) gate;
        // widening is exact. Preserve Float kind even for a whole-number value.
        let float = value
            .as_f64()
            .ok_or_else(|| reject("Double requires a finite safe number"))?;
        return serde_json::Number::from_f64(float)
            .map(Value::Number)
            .ok_or_else(|| reject("Double requires a finite safe number"));
    }
    Ok(value.clone())
}
/// Codec-neutral checked kind, not a new guest wire ABI. A declaration-aware
/// encoder must match these variants to native kinds / final guest scalar tags
/// for arguments AND each row field. JSON/JCS spelling cannot recover kind.
#[derive(Clone, Debug, PartialEq)]
pub enum CheckedScalar {
    Null,
    Int(i64),
    Double(f64),
    Bool(bool),
    String(String),
}
pub fn checked_scalar(value: &Value, field: &ScalarField) -> Result<CheckedScalar> {
    let value = cell(value, field)?;
    Ok(match value {
        Value::Null => CheckedScalar::Null,
        Value::Bool(v) => CheckedScalar::Bool(v),
        Value::String(v) => CheckedScalar::String(v),
        Value::Number(v) if v.is_f64() => {
            CheckedScalar::Double(v.as_f64().expect("checked finite double"))
        }
        Value::Number(v) => CheckedScalar::Int(v.as_i64().expect("checked safe integer")),
        _ => unreachable!("cell refuses collections"),
    })
}
/// No query fetching/truncation here: callers must fetch cap+1 and refuse a
/// truncated SQL receipt before calling. P1 complete-binding/string/row caps
/// remain authoritative in the guest. Empty One is distinct from a null cell.
pub fn scalar_rows(
    input: &RuleInputDecl,
    rows: &[BTreeMap<String, Value>],
    truncated: bool,
) -> Result<Value> {
    if truncated {
        return Err(reject("rule input query truncated; narrow SQL or select a deterministic winner, never evaluate a partial result"));
    }
    if input.cardinality == RuleCardinality::One && rows.len() > 1 {
        return Err(reject("One input returned more than one row; use a proved deterministic ORDER BY ... LIMIT 1 winner or narrow the key"));
    }
    let contract = input.contract.as_ref().ok_or_else(|| {
        reject("scalar_rows bridge requires scalar_rows_v1; legacy replay is not new admission")
    })?;
    // Field vectors are semantically unordered in the immutable digest.
    // Pair order is therefore unsigned UTF-8 byte order of names, independently
    // of declarations/query-driver order. JS must sort explicit pairs with a
    // TextEncoder byte comparator, not Object enumeration / default UTF-16 sort.
    let mut fields = contract.fields().iter().collect::<Vec<_>>();
    fields.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    let mut values = Vec::new();
    for row in rows {
        validate_output_labels(input, &row.keys().cloned().collect::<Vec<_>>())?;
        let mut object = serde_json::Map::new();
        for field in &fields {
            let value = row
                .get(&field.name)
                .ok_or_else(|| reject("missing output field is not SQL null or false"))?;
            object.insert(field.name.clone(), cell(value, field)?);
        }
        values.push(Value::Object(object));
    }
    Ok(match input.cardinality {
        RuleCardinality::One => values.pop().unwrap_or(Value::Null),
        RuleCardinality::Many => Value::Array(values),
    })
}
/// Engine-neutral plan corresponding to PR2 draft InputShape; adapters map to
/// the ABI type, rather than using this as a second versioned wire schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineShape {
    pub name: String,
    pub cardinality: EngineCardinality,
    pub scalar_type: Option<ScalarType>,
    pub nullable: bool,
    pub required_when: Option<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineCardinality {
    One,
    Many,
    Scalar,
}
pub fn engine_shapes(revision: &RuleRevision) -> Result<Vec<EngineShape>> {
    ri::validate_revision_shape(revision)?;
    if revision.binding_contract.is_none() {
        return Err(reject(
            "engine bridge requires new versioned input contract",
        ));
    }
    let mut shapes = Vec::new();
    for name in ri::derive_input_order(revision)? {
        let input = revision
            .inputs
            .iter()
            .find(|i| i.name == name)
            .expect("derived name");
        shapes.push(EngineShape {
            name,
            cardinality: match input.cardinality {
                RuleCardinality::One => EngineCardinality::One,
                RuleCardinality::Many => EngineCardinality::Many,
            },
            scalar_type: None,
            nullable: false,
            required_when: input
                .contract
                .as_ref()
                .and_then(|c| c.required_when())
                .map(|g| g.expression.clone()),
        });
    }
    let mut arguments = revision.scalar_arguments.iter().collect::<Vec<_>>();
    arguments.sort_by(|a, b| a.name.cmp(&b.name));
    shapes.extend(arguments.into_iter().map(|s| EngineShape {
        name: s.name.clone(),
        cardinality: EngineCardinality::Scalar,
        scalar_type: Some(s.scalar_type),
        nullable: s.nullable,
        required_when: None,
    }));
    Ok(shapes)
}
/// Bind exactly the admitted declarations. Only Argument sources accept caller
/// values. Completion sources require an authorized host context and cannot be
/// supplied through the argument map; no metadata injects extra engine names.
/// The real adapter supplies its captured host time/context and caps the result.
pub fn bind_scalars(
    revision: &RuleRevision,
    arguments: &BTreeMap<String, Value>,
    now_ms: i64,
    context: Option<&crate::mcp::advisors::AdviceContext>,
) -> Result<BTreeMap<String, Value>> {
    ri::validate_revision_shape(revision)?;
    if revision.binding_contract.is_none() {
        return Err(reject("scalar binding requires scalar_rows_v1"));
    }
    let expected = revision
        .scalar_arguments
        .iter()
        .filter(|s| s.source == ScalarSource::Argument)
        .map(|s| s.name.as_str())
        .collect::<BTreeSet<_>>();
    if expected != arguments.keys().map(String::as_str).collect() {
        return Err(reject("caller arguments must exactly match declared Argument sources; host facts/time cannot be injected"));
    }
    let mut bindings = BTreeMap::new();
    for scalar in &revision.scalar_arguments {
        let value = match scalar.source {
            ScalarSource::Argument => arguments[&scalar.name].clone(),
            ScalarSource::NowMs => Value::from(now_ms),
            ScalarSource::CompletionV1 { fact } => {
                let ctx = context.ok_or_else(|| reject("completion_v1 requires an authorized advisor host context; unavailable to ordinary callables"))?;
                completion_fact(ctx, fact)
                    .map(Value::Bool)
                    .unwrap_or(Value::Null)
            }
        };
        if scalar.scalar_type == ScalarType::Bool && !value.is_null() && !value.is_boolean() {
            return Err(reject("scalar bool arguments require typed booleans"));
        }
        let field = ScalarField {
            name: scalar.name.clone(),
            scalar_type: scalar.scalar_type,
            nullable: scalar.nullable,
            canonical_integer_text: false,
        };
        bindings.insert(scalar.name.clone(), cell(&value, &field)?);
    }
    Ok(bindings)
}
/// Pure mapping of authorized host observations; no serde/caller deserializer.
/// The production adapter must obtain AdviceContext through the authorized
/// postcommit hook. This helper itself grants no read capability.
pub fn completion_fact(
    ctx: &crate::mcp::advisors::AdviceContext,
    fact: CompletionFact,
) -> Option<bool> {
    match fact {
        CompletionFact::CompletionTransition => {
            if ctx.record_type != "WorkItem" {
                return Some(false);
            }
            let after = ctx.lifecycle_after_terminality.as_deref()?;
            Some(
                after == "terminal_positive"
                    && !matches!(
                        ctx.lifecycle_before_terminality.as_deref(),
                        Some("terminal_positive" | "terminal_negative")
                    ),
            )
        }
        CompletionFact::SummaryPresent => ctx.summary_present,
        CompletionFact::SummaryChangedInWrite => ctx.summary_changed_in_write,
        CompletionFact::SummaryChangedSinceActive => ctx.summary_changed_since_active,
        CompletionFact::ClaimHeld => ctx.claim_held,
        CompletionFact::WriterHoldsClaim => ctx.writer_holds_claim,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn reordered_field_declarations_share_digest_pairs_and_native_map_costs() {
        let names = ["2", "10", "a", "Z", "\u{10000}", "\u{e000}"];
        let mut r = revision();
        r.inputs.truncate(1);
        r.inputs[0].name = "row".into();
        r.inputs[0].sql =
            "SELECT 1 AS \"2\",1 AS \"10\",1 AS a,1 AS Z,1 AS \"𐀀\",1 AS \"\"".into();
        r.inputs[0].required_fields = names.iter().map(|n| n.to_string()).collect();
        let fields = names
            .iter()
            .map(|name| ScalarField {
                name: name.to_string(),
                scalar_type: ScalarType::Int,
                nullable: false,
                canonical_integer_text: false,
            })
            .collect::<Vec<_>>();
        r.inputs[0].contract = Some(RuleInputContract::ScalarRowsV1 {
            fields,
            required_when: None,
        });
        let mut reversed = r.clone();
        let RuleInputContract::ScalarRowsV1 { fields, .. } =
            reversed.inputs[0].contract.as_mut().unwrap();
        fields.reverse();
        assert_eq!(
            ri::revision_digest(&r).unwrap(),
            ri::revision_digest(&reversed).unwrap()
        );
        let rows = [names
            .iter()
            .map(|n| (n.to_string(), json!(1)))
            .collect::<BTreeMap<_, _>>()];
        let a = scalar_rows(&r.inputs[0], &rows, false).unwrap();
        let b = scalar_rows(&reversed.inputs[0], &rows, false).unwrap();
        let ordered = ["10", "2", "Z", "a", "\u{e000}", "\u{10000}"];
        for value in [&a, &b] {
            assert_eq!(
                value
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                ordered
            );
        }
        assert_eq!(
            serde_json::to_vec(&a).unwrap(),
            serde_json::to_vec(&b).unwrap()
        );
        // Compare explicit final tagged pair order as well as insertion-ordered
        // JSON bytes. Numeric labels and BMP/astral labels catch JS order traps.
        let pairs = |value: &Value| {
            value
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| json!([{ "string":k },{ "int":v.as_i64().unwrap().to_string() }]))
                .collect::<Vec<_>>()
        };
        assert_eq!(pairs(&a), pairs(&b));
        let declarations = cel::Declarations::new(
            [cel::InputDecl {
                name: "row".into(),
                kind: cel::InputKind::One,
            }],
            &cel::Policy::P1,
        )
        .unwrap();
        let native = |value: &Value| {
            cel::Value::from(
                value
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(k, v)| (k.clone(), cel::Value::Int(v.as_i64().unwrap())))
                    .collect::<indexmap::IndexMap<_, _>>(),
            )
        };
        let eval = |source: &str, value: &Value| {
            let prepared = cel::check(source, &declarations, &cel::Policy::P1)
                .result
                .expect("supported P1 map macro");
            let mut bindings = cel::Bindings::empty(&declarations, &cel::Policy::P1);
            bindings.insert("row", &native(value)).unwrap();
            cel::evaluate(&prepared, &bindings, &cel::Policy::P1)
        };
        for source in [
            "row.map(k,k)",
            "row.exists(k,k == '10')",
            "row.exists(k,k == 'a')",
        ] {
            let first = eval(source, &a);
            let second = eval(source, &b);
            assert_eq!(first.result.unwrap(), second.result.unwrap());
            assert_eq!(first.cost, second.cost);
            assert_eq!(first.input_cost, second.input_cost);
        }
        let keys = eval("row.map(k,k)", &a).result.unwrap();
        assert_eq!(
            keys,
            cel::Value::from(
                ordered
                    .iter()
                    .map(|s| cel::Value::from(*s))
                    .collect::<Vec<_>>()
            )
        );
        let early = eval("row.exists(k,k == '10')", &a);
        let late = eval("row.exists(k,k == 'a')", &a);
        assert!(
            early.cost.work < late.cost.work,
            "short-circuit order must be observable"
        );
        println!(
            "normalized map exists: first={} WU, fourth={} WU",
            early.cost.work, late.cost.work
        );
    }
    #[test]
    fn double_widening_preserves_declared_native_kind_for_args_and_rows() {
        let double = ScalarField {
            name: "v".into(),
            scalar_type: ScalarType::Double,
            nullable: true,
            canonical_integer_text: false,
        };
        let decl = cel::Declarations::new(
            [cel::InputDecl {
                name: "v".into(),
                kind: cel::InputKind::Scalar {
                    kind: cel::ScalarType::Double,
                    nullable: true,
                },
            }],
            &cel::Policy::P1,
        )
        .unwrap();
        assert!(cel::Bindings::empty(&decl, &cel::Policy::P1)
            .insert("v", &cel::Value::Int(1))
            .is_err());
        let mut revision = revision();
        revision.scalar_arguments = vec![ScalarArgument {
            name: "v".into(),
            scalar_type: ScalarType::Double,
            nullable: true,
            source: ScalarSource::Argument,
        }];
        let mut row_input = input("row", RuleCardinality::One);
        row_input.contract = Some(RuleInputContract::ScalarRowsV1 {
            fields: vec![double.clone()],
            required_when: None,
        });
        for raw in [
            json!(1),
            json!(-1),
            json!(1.5),
            json!(9007199254740991i64),
            json!(-9007199254740991i64),
            json!(-0.0),
        ] {
            let args = bind_scalars(
                &revision,
                &BTreeMap::from([("v".into(), raw.clone())]),
                0,
                None,
            )
            .unwrap();
            let rows = scalar_rows(
                &row_input,
                &[BTreeMap::from([("v".into(), raw.clone())])],
                false,
            )
            .unwrap();
            for value in [&args["v"], &rows["v"]] {
                assert!(value.is_f64(), "{raw}: {value:?}");
                let CheckedScalar::Double(float) = checked_scalar(value, &double).unwrap() else {
                    panic!("Double kind lost");
                };
                assert_eq!(float.to_bits(), raw.as_f64().unwrap().to_bits());
                // The adapter must select the explicit double scalar tag/kind
                // from checked declarations, even when JSON prints a whole number.
                let native = cel::Value::Float(float);
                assert!(cel::Bindings::empty(&decl, &cel::Policy::P1)
                    .insert("v", &native)
                    .is_ok());
                let tagged = json!({"double":float});
                let decoded = cel::Value::Float(tagged["double"].as_f64().unwrap());
                assert!(cel::Bindings::empty(&decl, &cel::Policy::P1)
                    .insert("v", &decoded)
                    .is_ok());
            }
        }
        for raw in [
            json!(9007199254740992u64),
            json!(-9007199254740992i64),
            json!(1e100),
            json!(true),
            json!("1"),
            json!([]),
        ] {
            assert!(bind_scalars(
                &revision,
                &BTreeMap::from([("v".into(), raw.clone())]),
                0,
                None
            )
            .is_err());
            assert!(
                scalar_rows(&row_input, &[BTreeMap::from([("v".into(), raw)])], false).is_err()
            );
        }
        assert_eq!(
            checked_scalar(&Value::Null, &double).unwrap(),
            CheckedScalar::Null
        );
        let nonnull = ScalarField {
            nullable: false,
            ..double.clone()
        };
        assert!(checked_scalar(&Value::Null, &nonnull).is_err());
        let int = ScalarField {
            scalar_type: ScalarType::Int,
            ..double.clone()
        };
        assert!(checked_scalar(&json!(1.0), &int).is_err());
        let any = ScalarField {
            scalar_type: ScalarType::Any,
            ..double.clone()
        };
        assert_eq!(
            checked_scalar(&json!(1), &any).unwrap(),
            CheckedScalar::Int(1)
        );
        assert_eq!(
            checked_scalar(&json!(1.0), &any).unwrap(),
            CheckedScalar::Double(1.0)
        );
        assert!(serde_json::Number::from_f64(f64::INFINITY).is_none());
        assert!(serde_json::Number::from_f64(f64::NAN).is_none());
        let boolean = ScalarField {
            scalar_type: ScalarType::Bool,
            ..double
        };
        assert_eq!(
            checked_scalar(&json!(0), &boolean).unwrap(),
            CheckedScalar::Bool(false)
        );
        assert_eq!(
            checked_scalar(&json!(1), &boolean).unwrap(),
            CheckedScalar::Bool(true)
        );
        assert!(checked_scalar(&json!(2), &boolean).is_err());
        revision.scalar_arguments[0].scalar_type = ScalarType::Bool;
        assert!(bind_scalars(
            &revision,
            &BTreeMap::from([("v".into(), json!(1))]),
            0,
            None
        )
        .is_err());
    }
    #[test]
    fn completion_arguments_preserve_unknown_and_completed_only() {
        let mut ctx = crate::mcp::advisors::AdviceContext {
            tool: "update_record".into(),
            record_id: "task".into(),
            record_type: "WorkItem".into(),
            record_kind: "task".into(),
            record_name: None,
            body_chars_before: None,
            body_chars_after: None,
            recent_body_revisions: None,
            recent_same_run_append_streak: None,
            links_out_count: None,
            mentions_out_count: None,
            run_key: None,
            lifecycle_before: Some("in_progress".into()),
            lifecycle_after: Some("completed".into()),
            lifecycle_before_terminality: Some("open".into()),
            lifecycle_after_terminality: Some("terminal_positive".into()),
            summary_changed_in_write: Some(false),
            summary_changed_since_active: None,
            summary_present: Some(true),
            claim_held: Some(false),
            writer_holds_claim: None,
        };
        assert_eq!(
            completion_fact(&ctx, CompletionFact::CompletionTransition),
            Some(true)
        );
        assert_eq!(
            completion_fact(&ctx, CompletionFact::SummaryChangedInWrite),
            Some(false)
        );
        assert_eq!(
            completion_fact(&ctx, CompletionFact::SummaryChangedSinceActive),
            None
        );
        assert_eq!(
            completion_fact(&ctx, CompletionFact::ClaimHeld),
            Some(false)
        );
        assert_eq!(
            completion_fact(&ctx, CompletionFact::WriterHoldsClaim),
            None
        );
        let mut zero = revision();
        zero.inputs.clear();
        zero.scalar_arguments = [
            ("completed", CompletionFact::CompletionTransition),
            ("present", CompletionFact::SummaryPresent),
            ("changed", CompletionFact::SummaryChangedInWrite),
            ("since_active", CompletionFact::SummaryChangedSinceActive),
            ("held", CompletionFact::ClaimHeld),
            ("writer", CompletionFact::WriterHoldsClaim),
        ]
        .into_iter()
        .map(|(name, fact)| ScalarArgument {
            name: name.into(),
            scalar_type: ScalarType::Bool,
            nullable: true,
            source: ScalarSource::CompletionV1 { fact },
        })
        .collect();
        let bound = bind_scalars(&zero, &BTreeMap::new(), 0, Some(&ctx)).unwrap();
        assert_eq!(
            serde_json::to_value(bound).unwrap(),
            json!({
                "completed":true,"present":true,"changed":false,
                "since_active":null,"held":false,"writer":null
            })
        );
        ctx.lifecycle_after_terminality = Some("terminal_negative".into());
        assert_eq!(
            completion_fact(&ctx, CompletionFact::CompletionTransition),
            Some(false)
        );
        ctx.lifecycle_after_terminality = None;
        assert_eq!(
            completion_fact(&ctx, CompletionFact::CompletionTransition),
            None
        );
        ctx.lifecycle_after_terminality = Some("terminal_positive".into());
        ctx.lifecycle_before_terminality = Some("terminal_positive".into());
        assert_eq!(
            completion_fact(&ctx, CompletionFact::CompletionTransition),
            Some(false)
        );
    }
    fn input(name: &str, kind: RuleCardinality) -> RuleInputDecl {
        RuleInputDecl {
            name: name.into(),
            sql: "SELECT id FROM records ORDER BY id".into(),
            cardinality: kind,
            required_fields: vec!["id".into()],
            parameters: vec![],
            contract: Some(RuleInputContract::ScalarRowsV1 {
                fields: vec![ScalarField {
                    name: "id".into(),
                    scalar_type: ScalarType::String,
                    nullable: false,
                    canonical_integer_text: false,
                }],
                required_when: None,
            }),
        }
    }
    fn revision() -> RuleRevision {
        RuleRevision {
            namespace: "test".into(),
            name: "bridge".into(),
            language: "cel-subset@1".into(),
            inputs: vec![
                input("z", RuleCardinality::One),
                input("a", RuleCardinality::One),
            ],
            clauses: "[{\"id\":\"ok\",\"when\":\"true\",\"result\":\"false\"}]".into(),
            examples: vec![],
            definition_pins: vec![],
            scalar_arguments: vec![],
            binding_contract: Some(BindingContractVersion::ScalarRowsV1),
        }
    }
    fn guard(input: &mut RuleInputDecl, dep: &str) {
        let RuleInputContract::ScalarRowsV1 { required_when, .. } =
            input.contract.as_mut().unwrap();
        *required_when = Some(RequiredWhen {
            expression: format!("{dep} != null"),
            inputs: vec![dep.into()],
        });
    }
    #[test]
    fn legacy_digest_and_replay_identity_are_unchanged() {
        let legacy = json!({"namespace":"test","name":"old","language":"cel-subset@1","inputs":[{"name":"r","sql":"SELECT id FROM records","cardinality":"one","required_fields":["id"],"parameters":[]}],"clauses":"true","examples":[],"definition_pins":[]});
        let revision: RuleRevision = serde_json::from_value(legacy.clone()).unwrap();
        assert_eq!(ri::canonical_revision_value(&revision), legacy);
        let digest = crate::canonical_json::digest_json(&legacy);
        assert_eq!(ri::revision_digest(&revision).unwrap(), digest);
        let settings = json!({});
        ri::verify_replay_revision(
            &revision,
            &digest,
            &settings,
            &ri::settings_digest(&settings).unwrap(),
        )
        .unwrap();
        assert!(engine_shapes(&revision).is_err());
        assert_eq!(serde_json::to_value(&revision).unwrap(), legacy);
    }
    #[test]
    fn new_semantics_enter_digest_and_unknown_versions_refuse() {
        let r = revision();
        let digest = ri::revision_digest(&r).unwrap();
        let mut reordered = r.clone();
        reordered.inputs.reverse();
        assert_eq!(ri::revision_digest(&reordered).unwrap(), digest);
        let mut changed = r.clone();
        guard(&mut changed.inputs[1], "z");
        assert_ne!(ri::revision_digest(&changed).unwrap(), digest);
        let after = ri::revision_digest(&changed).unwrap();
        let RuleInputContract::ScalarRowsV1 { required_when, .. } =
            changed.inputs[1].contract.as_mut().unwrap();
        required_when.as_mut().unwrap().expression.push(' ');
        assert_ne!(ri::revision_digest(&changed).unwrap(), after);
        let mut wire = serde_json::to_value(&r).unwrap();
        wire["inputs"][0]["contract"]["version"] = json!("v_future");
        assert!(serde_json::from_value::<RuleRevision>(wire).is_err());
        let mut wire = serde_json::to_value(&r).unwrap();
        wire["inputs"][0]["contract"]["budget"] = json!(99);
        assert!(serde_json::from_value::<RuleRevision>(wire).is_err());
        changed.inputs[0].contract = None;
        assert!(ri::validate_revision_shape(&changed).is_err());
    }
    #[test]
    fn guard_and_parameter_dependencies_share_order_and_cycles() {
        let mut r = revision();
        guard(&mut r.inputs[1], "z");
        assert_eq!(ri::derive_input_order(&r).unwrap(), ["z", "a"]);
        let shapes = engine_shapes(&r).unwrap();
        assert_eq!(shapes[1].required_when.as_deref(), Some("z != null"));
        guard(&mut r.inputs[0], "a");
        assert!(validate_contract(&r).is_err());
        let mut r = revision();
        guard(&mut r.inputs[1], "a");
        assert!(validate_contract(&r).is_err());
        let mut r = revision();
        guard(&mut r.inputs[1], "missing");
        assert!(validate_contract(&r).is_err());
        let mut r = revision();
        r.inputs[1].cardinality = RuleCardinality::Many;
        guard(&mut r.inputs[1], "z");
        assert!(validate_contract(&r).is_err());
        let mut r = revision();
        guard(&mut r.inputs[1], "z");
        r.inputs[0].parameters.push(ri::ParameterDecl {
            slot: 1,
            param_type: "text".into(),
            nullable: false,
            source: ParameterSource::InputRow {
                input: "a".into(),
                field: "id".into(),
            },
        });
        assert!(validate_contract(&r).is_err());
    }
    #[test]
    fn empty_one_null_cell_missing_and_false_stay_distinct() {
        let mut input = input("row", RuleCardinality::One);
        let RuleInputContract::ScalarRowsV1 { fields, .. } = input.contract.as_mut().unwrap();
        fields[0].scalar_type = ScalarType::Bool;
        fields[0].nullable = true;
        assert_eq!(scalar_rows(&input, &[], false).unwrap(), Value::Null);
        assert_eq!(
            scalar_rows(
                &input,
                &[BTreeMap::from([("id".into(), Value::Null)])],
                false
            )
            .unwrap(),
            json!({"id":null})
        );
        for false_value in [json!(false), json!(0)] {
            assert_eq!(
                scalar_rows(
                    &input,
                    &[BTreeMap::from([("id".into(), false_value)])],
                    false
                )
                .unwrap(),
                json!({"id":false})
            );
        }
        assert!(scalar_rows(&input, &[BTreeMap::new()], false).is_err());
        assert!(scalar_rows(&input, &[BTreeMap::from([("id".into(), json!(2))])], false).is_err());
        assert!(scalar_rows(&input, &[BTreeMap::new(), BTreeMap::new()], false).is_err());
        assert!(scalar_rows(&input, &[], true).is_err());
        input.cardinality = RuleCardinality::Many;
        assert_eq!(scalar_rows(&input, &[], false).unwrap(), json!([]));
        assert!(scalar_rows(&input, &[], true).is_err());
    }
    #[test]
    fn canonical_money_never_truncates_real_or_fractional_text() {
        let field = ScalarField {
            name: "amount".into(),
            scalar_type: ScalarType::Int,
            nullable: false,
            canonical_integer_text: true,
        };
        assert_eq!(cell(&json!("2100"), &field).unwrap(), json!(2100));
        for value in [
            json!(2100.5),
            json!(2100),
            json!("2100.5"),
            json!("2.1e3"),
            json!("02100"),
            json!("+2"),
            json!("-0"),
            json!(" 2"),
            json!("9007199254740992"),
        ] {
            assert!(cell(&value, &field).is_err(), "{value}");
        }
        assert_eq!(cell(&json!("-21"), &field).unwrap(), json!(-21));
    }
    #[test]
    fn scalar_shape_and_argument_sources_are_fail_closed() {
        let mut r = revision();
        let scalar = ScalarArgument {
            name: "now_ms".into(),
            scalar_type: ScalarType::Int,
            nullable: false,
            source: ScalarSource::NowMs,
        };
        r.scalar_arguments.push(scalar);
        assert_eq!(
            engine_shapes(&r).unwrap()[2].cardinality,
            EngineCardinality::Scalar
        );
        let mut bad = r.clone();
        bad.scalar_arguments[0].nullable = true;
        assert!(validate_contract(&bad).is_err());
        let mut bad = r.clone();
        bad.scalar_arguments[0].name = "a".into();
        assert!(validate_contract(&bad).is_err());
        let digest = ri::revision_digest(&r).unwrap();
        let mut changed = r.clone();
        changed.scalar_arguments[0].source = ScalarSource::Argument;
        assert_ne!(ri::revision_digest(&changed).unwrap(), digest);
        let mut zero_sql = revision();
        zero_sql.inputs.clear();
        zero_sql.scalar_arguments = vec![ScalarArgument {
            name: "completed".into(),
            scalar_type: ScalarType::Bool,
            nullable: true,
            source: ScalarSource::CompletionV1 {
                fact: CompletionFact::CompletionTransition,
            },
        }];
        assert_eq!(engine_shapes(&zero_sql).unwrap().len(), 1);
        assert!(bind_scalars(&zero_sql, &BTreeMap::new(), 0, None).is_err());
        let injected = BTreeMap::from([("completed".into(), json!(true))]);
        assert!(bind_scalars(&zero_sql, &injected, 0, None).is_err());
        let mut legacy = zero_sql.clone();
        legacy.binding_contract = None;
        assert!(validate_contract(&legacy).is_err());
        let mut wire = serde_json::to_value(&zero_sql).unwrap();
        wire["binding_contract"] = json!("future_v2");
        assert!(serde_json::from_value::<RuleRevision>(wire).is_err());
        let field = ScalarField {
            name: "v".into(),
            scalar_type: ScalarType::Any,
            nullable: true,
            canonical_integer_text: false,
        };
        for value in [json!([]), json!({}), json!(9007199254740992u64)] {
            assert!(cell(&value, &field).is_err());
        }
    }
}
