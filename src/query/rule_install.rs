//! Shared pure rule revision/install/validator models (task 81c1d95).
//!
//! Shared pure rule revision/install/validator models (no storage authority):
//! immutable revision content, canonical digests, parameter DAG validation,
//! engine evidence binding, and the trusted validator seam from the
//! owner-accepted interface (docs/prototypes/rule_validation_interface.md).
//! This module itself does no I/O: the gated storage (`meta/
//! rule_installation`), admission/call wrappers (`rule_registry`), and K6a
//! collector (`dependency`) enforce these guards at runtime, and replay
//! never prepares SQL. The fixture validator and its identity are test-only:
//! non-test paths must refuse fixture evidence.

#![allow(dead_code)] // Shared pure models; operational v1 intake remains closed.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::sql_contract::{self, QuerySqlErrorCategory};
use crate::error::{Error, Result};

fn refuse(detail: impl AsRef<str>) -> Error {
    sql_contract::categorized_error(QuerySqlErrorCategory::UnsafeStatement, detail)
}

fn malformed(detail: impl AsRef<str>) -> Error {
    sql_contract::categorized_error(QuerySqlErrorCategory::InvalidArguments, detail)
}

/// I-JSON safe-integer bound: cross-runtime (browser/JS/RFC8785) interop
/// requires integers within ±(2^53-1). The pinned serde_jcs writes integers
/// exactly, so this is an interoperability policy, not a claim about the
/// current formatter: large values must be tagged strings.
pub const MAX_SAFE_INTEGER_I64: i64 = 9_007_199_254_740_991;

/// Recursively refuse JSON numbers outside the safe range. Finite fractional
/// numbers within range stay allowed — only magnitude is policed, never
/// integrality. Strings (including tagged-string big integers), booleans and
/// nulls always pass.
pub fn check_safe_numbers(value: &serde_json::Value) -> Result<()> {
    match value {
        serde_json::Value::Number(number) => {
            let outside = if let Some(int) = number.as_i64() {
                !(-MAX_SAFE_INTEGER_I64..=MAX_SAFE_INTEGER_I64).contains(&int)
            } else if let Some(uint) = number.as_u64() {
                uint > MAX_SAFE_INTEGER_I64 as u64
            } else if let Some(float) = number.as_f64() {
                float.abs() > MAX_SAFE_INTEGER_I64 as f64
            } else {
                false
            };
            if outside {
                return Err(malformed(format!(
                    "rule JSON number {number} is outside the interoperable ±2^53-1 range; use a tagged string"
                )));
            }
            Ok(())
        }
        serde_json::Value::Array(items) => items.iter().try_for_each(check_safe_numbers),
        serde_json::Value::Object(fields) => fields.values().try_for_each(check_safe_numbers),
        _ => Ok(()),
    }
}

fn validate_token(kind: &str, part: &str) -> Result<()> {
    if part.is_empty() || part.len() > 128 {
        return Err(malformed(format!("rule {kind} must be 1..128 bytes")));
    }
    if !part
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(malformed(format!(
            "rule {kind} '{part}' must match [A-Za-z0-9._-]"
        )));
    }
    Ok(())
}

/// One-row or many-row declared input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleCardinality {
    One,
    Many,
}

/// Where one declared parameter value comes from: a NAMED call argument (so a
/// binding shared by slots across inputs stays identifiable), a field of
/// another input's row, or the explicit host time source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum ParameterSource {
    Argument { name: String },
    InputRow { input: String, field: String },
    NowMs,
}

/// One declared `?N` binding: the slot, its SQL type, nullability, and value
/// source. The type tag must come from the shared parameter registry
/// (`PARAMETER_TYPES`); null arrives as explicit JSON null for any tag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterDecl {
    pub slot: usize,
    pub param_type: String,
    pub nullable: bool,
    pub source: ParameterSource,
}

/// One declared input: exact SQL bytes, cardinality, required output fields,
/// and typed parameter sources. Row sources may name any existing one-row
/// input; acyclicity is enforced by DAG validation, not by declaration order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleInputDecl {
    pub name: String,
    pub sql: String,
    pub cardinality: RuleCardinality,
    pub required_fields: Vec<String>,
    pub parameters: Vec<ParameterDecl>,
    /// Proposed PR4a bridge. Omission preserves the legacy gated digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<super::rule_shape::RuleInputContract>,
}

/// One optional opaque R9 example: the registry stores it, the engine runs it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleExample {
    pub name: String,
    pub body: serde_json::Value,
}

/// One separate explicit v2 definition pin (the tag K6a preflights).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionPin {
    pub family: String,
    pub version: u32,
    pub digest: String,
}

/// Immutable rule content. The digest covers the clause LANGUAGE identity
/// (for example `cel-subset@1`), never the concrete engine build: engine
/// version and bundle travel in validation evidence and the K4 evaluation
/// pin, so an engine upgrade cannot silently mint new revisions of every
/// rule. Clauses are inert exact bytes, opaque to the registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleRevision {
    pub namespace: String,
    pub name: String,
    pub language: String,
    pub inputs: Vec<RuleInputDecl>,
    pub clauses: String,
    pub examples: Vec<RuleExample>,
    pub definition_pins: Vec<DefinitionPin>,
    /// Absence retains exact legacy bytes/digest; explicit version admits zero-SQL rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_contract: Option<super::rule_shape::BindingContractVersion>,
    /// Explicit scalar args/time/authorized facts for the new contract only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scalar_arguments: Vec<super::rule_shape::ScalarArgument>,
}

/// Canonical JSON value of a revision for digesting. Key order never matters
/// (JCS sorts object keys), but semantically unordered arrays are sorted here:
/// inputs (by name), required fields, parameters (by slot), examples (by
/// name) and definition pins (by family). Declaration order never moves the
/// digest; evaluation order derives separately from the DAG. SQL and clauses
/// hash as exact bytes, never normalized: any byte change is a new revision.
pub fn canonical_revision_value(revision: &RuleRevision) -> serde_json::Value {
    let mut ordered: Vec<&RuleInputDecl> = revision.inputs.iter().collect();
    ordered.sort_by(|a, b| a.name.cmp(&b.name));
    let inputs: Vec<serde_json::Value> = ordered
        .iter()
        .map(|input| {
            let mut fields: Vec<&str> = input.required_fields.iter().map(String::as_str).collect();
            fields.sort_unstable();
            let mut parameters: Vec<&ParameterDecl> = input.parameters.iter().collect();
            parameters.sort_by_key(|declared| declared.slot);
            let mut value = serde_json::json!({
                "name": input.name,
                "sql": input.sql,
                "cardinality": match input.cardinality {
                    RuleCardinality::One => "one",
                    RuleCardinality::Many => "many",
                },
                "required_fields": fields,
                "parameters": parameters
                    .into_iter()
                    .map(canonical_parameter_value)
                    .collect::<Vec<_>>(),
            });
            if let Some(contract) = &input.contract {
                value["contract"] = contract.canonical_value();
            }
            value
        })
        .collect();
    let mut examples: Vec<&RuleExample> = revision.examples.iter().collect();
    examples.sort_by(|a, b| a.name.cmp(&b.name));
    let mut pins: Vec<&DefinitionPin> = revision.definition_pins.iter().collect();
    pins.sort_by(|a, b| a.family.cmp(&b.family));
    let mut value = serde_json::json!({
        "namespace": revision.namespace,
        "name": revision.name,
        "language": revision.language,
        "inputs": inputs,
        "clauses": revision.clauses,
        "examples": examples.iter().map(|e| serde_json::json!({"name": e.name, "body": e.body})).collect::<Vec<_>>(),
        "definition_pins": pins.iter().map(|p| serde_json::json!({"family": p.family, "version": p.version, "digest": p.digest})).collect::<Vec<_>>(),
    });
    if let Some(version) = revision.binding_contract {
        value["binding_contract"] = serde_json::to_value(version).expect("binding version");
    }
    if !revision.scalar_arguments.is_empty() {
        let mut scalars = revision.scalar_arguments.clone();
        scalars.sort_by(|a, b| a.name.cmp(&b.name));
        value["scalar_arguments"] = serde_json::to_value(scalars).expect("scalar declarations");
    }
    value
}

fn canonical_parameter_value(declared: &ParameterDecl) -> serde_json::Value {
    match &declared.source {
        ParameterSource::Argument { name } => serde_json::json!({
            "slot": declared.slot, "type": declared.param_type,
            "nullable": declared.nullable, "source": "argument", "name": name,
        }),
        ParameterSource::InputRow { input, field } => serde_json::json!({
            "slot": declared.slot, "type": declared.param_type,
            "nullable": declared.nullable, "source": "input_row",
            "input": input, "field": field,
        }),
        ParameterSource::NowMs => serde_json::json!({
            "slot": declared.slot, "type": declared.param_type,
            "nullable": declared.nullable, "source": "now_ms",
        }),
    }
}

/// SHA-256 over the canonical revision value (shared canonical_json).
/// Fallible: canonical numbers outside the interoperable range are refused
/// before hashing, so unsafe content can never reach the digest boundary.
pub fn revision_digest(revision: &RuleRevision) -> Result<String> {
    let canonical = canonical_revision_value(revision);
    check_safe_numbers(&canonical)?;
    Ok(crate::canonical_json::digest_json(&canonical))
}

/// SHA-256 over engine settings, which must be a JSON object OUTSIDE the
/// revision digest: engine-owned, engine-validated, never interpreted here.
pub fn settings_digest(settings: &serde_json::Value) -> Result<String> {
    if !settings.is_object() {
        return Err(malformed("rule engine settings must be a JSON object"));
    }
    check_safe_numbers(settings)?;
    Ok(crate::canonical_json::digest_json(settings))
}

/// Canonical admission-evidence digest binding the COMPLETE read-set: global
/// catalog/profile pins plus per-input relation/column/slot pins. Inputs and
/// relations sort by name and slots ascending (defensive: digest must not
/// depend on caller order). The host binds this into the private receipt;
/// fold and keyed reads recompute it.
pub fn readset_digest(
    catalog_revision: u32,
    profile_id: &str,
    profile_revision: u32,
    inputs: &[(
        &str,
        &native_query_contract::rule_contract::RuleInputReadset,
    )],
) -> String {
    let mut ordered: Vec<(
        &str,
        &native_query_contract::rule_contract::RuleInputReadset,
    )> = inputs.to_vec();
    ordered.sort_by(|a, b| a.0.cmp(b.0));
    let inputs_value: Vec<serde_json::Value> = ordered
        .iter()
        .map(|(name, readset)| {
            let mut relations: Vec<&native_query_contract::rule_contract::PinnedRelation> =
                readset.relations.iter().collect();
            relations.sort_by(|a, b| a.name.cmp(&b.name));
            let mut slots = readset.parameter_slots.clone();
            slots.sort_unstable();
            serde_json::json!({
                "name": name,
                "relations": relations.iter().map(|r| {
                    let mut columns: Vec<&String> = r.columns.iter().collect();
                    columns.sort();
                    serde_json::json!({
                        "identity": r.identity, "name": r.name,
                        "version": r.semantic_version, "columns": columns,
                        "population_only": r.population_only,
                    })
                }).collect::<Vec<_>>(),
                "slots": slots,
                "uses_now_ms": readset.uses_now_ms,
            })
        })
        .collect();
    crate::canonical_json::digest_json(&serde_json::json!({
        "catalog_revision": catalog_revision,
        "profile": {"id": profile_id, "revision": profile_revision},
        "inputs": inputs_value,
    }))
}

/// Shape validation of revision content (no SQL parsing here — extraction
/// owns that): tokens, non-emptiness, and uniqueness. Label subsets, slots,
/// and DAG edges are validated by [`validate_parameter_dag`] against the
/// host-derived output labels and read-sets.
pub fn validate_revision_shape(revision: &RuleRevision) -> Result<()> {
    super::rule_shape::validate_contract(revision)?;
    validate_token("namespace", &revision.namespace)?;
    validate_token("name", &revision.name)?;
    if revision.language.is_empty() || revision.language.len() > 128 {
        return Err(malformed("rule language must be 1..128 bytes"));
    }
    if !revision
        .language
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' || c == '@')
    {
        return Err(malformed(format!(
            "rule language '{}' must match [A-Za-z0-9._@-]",
            revision.language
        )));
    }
    if revision.clauses.is_empty() {
        return Err(malformed("rule clauses must not be empty"));
    }
    if revision.inputs.is_empty() && revision.binding_contract.is_none() {
        return Err(malformed("rule revision must declare at least one input"));
    }
    let mut names = BTreeSet::new();
    for input in &revision.inputs {
        validate_token("input name", &input.name)?;
        if !names.insert(&input.name) {
            return Err(malformed(format!(
                "rule input '{}' is declared twice",
                input.name
            )));
        }
        if input.sql.is_empty() {
            return Err(malformed(format!(
                "rule input '{}' SQL must not be empty",
                input.name
            )));
        }
        // Duplicate slots refuse here too: the DAG length check alone would
        // leave replay/shape verification without the refusal.
        let mut slots = BTreeSet::new();
        for declared in &input.parameters {
            if !slots.insert(declared.slot) {
                return Err(malformed(format!(
                    "rule input '{}' declares slot ?{} twice",
                    input.name, declared.slot
                )));
            }
            if declared.slot == 0 {
                return Err(malformed(format!(
                    "rule input '{}' parameter slots use ?N numbering from 1",
                    input.name
                )));
            }
            if !super::sql_contract::parameter_type_known(&declared.param_type) {
                return Err(malformed(format!(
                    "rule input '{}' declares unknown parameter type '{}'",
                    input.name, declared.param_type
                )));
            }
            match &declared.source {
                ParameterSource::Argument { name } => validate_token("argument name", name)?,
                ParameterSource::InputRow {
                    input: source,
                    field,
                } => {
                    validate_token("source input name", source)?;
                    if field.is_empty() {
                        return Err(malformed(format!(
                            "rule input '{}' sources an empty field name",
                            input.name
                        )));
                    }
                }
                ParameterSource::NowMs => {}
            }
        }
    }
    let mut examples = BTreeSet::new();
    for example in &revision.examples {
        if example.name.is_empty() || example.name.len() > 128 {
            return Err(malformed("rule example name must be 1..128 bytes"));
        }
        if !examples.insert(&example.name) {
            return Err(malformed(format!(
                "rule example '{}' is declared twice",
                example.name
            )));
        }
        // Unsafe integers must be tagged strings, recursively, before hashing.
        check_safe_numbers(&example.body)?;
    }
    // Duplicate families would make K6a derivation ambiguous. Version numbering
    // follows the existing exact-pin identity semantics (definition_artifact's
    // family/version check deliberately ignores the u32 value), so no
    // version>0 refusal is invented here: v0 pins are preserved.
    let mut families = BTreeSet::new();
    for pin in &revision.definition_pins {
        validate_token("definition family", &pin.family)?;
        if !families.insert(&pin.family) {
            return Err(malformed(format!(
                "rule definition family '{}' is pinned twice",
                pin.family
            )));
        }
        if pin.digest.len() != 64
            || !pin
                .digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(malformed(format!(
                "rule definition pin for '{}' must be 64 lowercase hex chars",
                pin.family
            )));
        }
    }
    Ok(())
}

/// Parameter DAG validation against host-derived evidence, returning the
/// stable evaluation order. Declared slots must exactly match the
/// authoritative extractor slots; required fields and row-source fields must
/// sit among the validated SQL output labels. Graph semantics (source-name /
/// cardinality / acyclicity) live in exactly one place — the shared pure
/// [`derive_input_order`] invoked below — so admission-time label/slot/
/// coherence checks never duplicate edge construction.
pub fn validate_parameter_dag(
    revision: &RuleRevision,
    readsets: &BTreeMap<String, native_query_contract::rule_contract::RuleInputReadset>,
    output_labels: &BTreeMap<String, Vec<String>>,
) -> Result<Vec<String>> {
    let mut arguments: BTreeMap<&str, (&str, bool)> = BTreeMap::new();
    for input in revision.inputs.iter() {
        let readset = readsets.get(&input.name).ok_or_else(|| {
            refuse(format!(
                "rule input '{}' has no derived read-set",
                input.name
            ))
        })?;
        let labels = output_labels.get(&input.name).ok_or_else(|| {
            refuse(format!(
                "rule input '{}' has no validated output labels",
                input.name
            ))
        })?;
        super::rule_shape::validate_output_labels(input, labels)?;
        if input.contract.is_some() {
            if readset.uses_now_ms {
                return Err(refuse("scalar_rows_v1 uses an explicit ?N NowMs parameter and declared scalar; replace hidden now_ms()"));
            }
            super::rule_order::validate_input_sql(input)?;
        }
        let declared: BTreeSet<usize> = input.parameters.iter().map(|p| p.slot).collect();
        let authoritative: BTreeSet<usize> = readset.parameter_slots.iter().copied().collect();
        if declared.len() != input.parameters.len() || declared != authoritative {
            return Err(refuse(format!(
                "rule input '{}' declares slots that do not exactly match the derived {:?}",
                input.name, readset.parameter_slots
            )));
        }
        if let Some(field) = input.required_fields.iter().find(|f| !labels.contains(f)) {
            return Err(refuse(format!(
                "rule input '{}' requires unknown field '{field}'",
                input.name
            )));
        }
        for parameter in &input.parameters {
            match &parameter.source {
                ParameterSource::Argument { name } => {
                    let binding = (parameter.param_type.as_str(), parameter.nullable);
                    if let Some(known) = arguments.insert(name.as_str(), binding) {
                        if known != binding {
                            return Err(refuse(format!(
                                "argument '{name}' is declared with conflicting types"
                            )));
                        }
                    }
                }
                ParameterSource::NowMs => {}
                ParameterSource::InputRow {
                    input: source,
                    field,
                } => {
                    let Some(position) = revision.inputs.iter().position(|i| &i.name == source)
                    else {
                        return Err(refuse(format!(
                            "rule input '{}' sources rows from unknown input '{source}'",
                            input.name
                        )));
                    };
                    if revision.inputs[position].cardinality != RuleCardinality::One {
                        return Err(refuse(format!(
                            "rule input '{}' sources rows from many-row input '{source}'",
                            input.name
                        )));
                    }
                    let source_labels = output_labels.get(source).ok_or_else(|| {
                        refuse(format!(
                            "rule input '{source}' has no validated output labels"
                        ))
                    })?;
                    if !source_labels.contains(field) {
                        return Err(refuse(format!(
                            "rule input '{}' sources unknown field '{field}' from '{source}'",
                            input.name
                        )));
                    }
                }
            }
        }
    }
    derive_input_order(revision)
}

/// Kahn's algorithm over deduped source -> target edges with a stable
/// name-ordered tie-break (independent of declaration order, like the digest).
/// Reports the inputs left unorderable as a cycle.
fn topological_order(
    revision: &RuleRevision,
    edges: &BTreeSet<(usize, usize)>,
) -> Result<Vec<String>> {
    let count = revision.inputs.len();
    let mut indegree = vec![0usize; count];
    let mut outgoing: Vec<Vec<usize>> = vec![Vec::new(); count];
    for &(from, to) in edges {
        outgoing[from].push(to);
        indegree[to] += 1;
    }
    // Name-based tie-break: the order never depends on declaration order,
    // matching the name-sorted digest.
    let mut ready: BTreeSet<(String, usize)> = (0..count)
        .filter(|&i| indegree[i] == 0)
        .map(|i| (revision.inputs[i].name.clone(), i))
        .collect();
    let mut order = Vec::with_capacity(count);
    while let Some(entry) = ready.iter().next().cloned() {
        ready.remove(&entry);
        order.push(entry.1);
        for &next in &outgoing[entry.1] {
            indegree[next] -= 1;
            if indegree[next] == 0 {
                ready.insert((revision.inputs[next].name.clone(), next));
            }
        }
    }
    if order.len() != count {
        let stuck = (0..count)
            .find(|&i| indegree[i] > 0)
            .expect("a cycle participant exists");
        return Err(refuse(format!(
            "rule inputs have a parameter cycle involving '{}'",
            revision.inputs[stuck].name
        )));
    }
    Ok(order
        .into_iter()
        .map(|i| revision.inputs[i].name.clone())
        .collect())
}

/// Pure input order from the immutable revision graph alone: name,
/// cardinality, and source edges plus Kahn name-ordered evaluation. No SQL
/// preparation, no output labels, no read-sets — the cheap derivation the
/// call gate re-runs from verified stored bytes. Admission separately runs
/// the full [`validate_parameter_dag`] against host-derived labels/read-sets.
pub fn derive_input_order(revision: &RuleRevision) -> Result<Vec<String>> {
    let mut edges: BTreeSet<(usize, usize)> = BTreeSet::new();
    for (index, input) in revision.inputs.iter().enumerate() {
        if let Some(guard) = input.contract.as_ref().and_then(|c| c.required_when()) {
            for source in &guard.inputs {
                let position = revision
                    .inputs
                    .iter()
                    .position(|i| &i.name == source)
                    .ok_or_else(|| {
                        refuse(format!(
                            "guard for '{}' depends on unknown input '{source}'",
                            input.name
                        ))
                    })?;
                edges.insert((position, index));
            }
        }
        for parameter in &input.parameters {
            let ParameterSource::InputRow { input: source, .. } = &parameter.source else {
                continue;
            };
            let Some(position) = revision.inputs.iter().position(|i| &i.name == source) else {
                return Err(refuse(format!(
                    "rule input '{}' sources rows from unknown input '{source}'",
                    input.name
                )));
            };
            if revision.inputs[position].cardinality != RuleCardinality::One {
                return Err(refuse(format!(
                    "rule input '{}' sources rows from many-row input '{source}'",
                    input.name
                )));
            }
            edges.insert((position, index));
        }
    }
    topological_order(revision, &edges)
}

/// Engine validation request: the immutable revision plus opaque settings,
/// with the host-computed digests the evidence must echo back. Engine
/// validation runs OUTSIDE the writer transaction; the writer rechecks
/// authority, ExpectedSeq, catalog/pins/digests before any append.
pub struct RuleValidationRequest<'a> {
    pub revision: &'a RuleRevision,
    pub settings: &'a serde_json::Value,
    pub revision_digest: &'a str,
    pub settings_digest: &'a str,
}

/// Engine evidence: echoes the request digests plus what the engine checked.
/// Concrete engine identity records who validated; version/bundle are
/// last-verified evidence only — call-time comparison uses language alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineValidationEvidence {
    pub revision_digest: String,
    pub settings_digest: String,
    pub language_identity: String,
    pub policy_version: String,
    pub engine_id: String,
    pub engine_version: String,
    pub bundle_sha256: Option<String>,
}

/// Trusted in-process validator seam. The host MUST invoke the synchronous
/// `validate` through `spawn_blocking` (or an equivalent off-Tokio worker)
/// BEFORE opening any writer transaction: validation can take tens of ms and
/// must never hold the workspace write lock. Requests stay borrowed and
/// in-process; a later host owns the `Arc` adapter plus owned
/// revision/settings copies for the blocking closure. The engine supplies the
/// real adapter (deterministic for revision/settings, step-budget bounded,
/// cannot crash the host, discards failed sandboxes, never reads the DB).
pub trait RuleValidator: Send + Sync {
    fn validate(
        &self,
        request: RuleValidationRequest<'_>,
    ) -> std::result::Result<EngineValidationEvidence, RuleValidationError>;
}

/// Proposed D3 adds cost refusal and deterministic engine fault. Existing
/// codes stay stable; only unavailable/saturated scheduling retries, never
/// deterministic traps or crashes. Registry mapping uses the code, never
/// string parsing; example failure also names the example.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum RuleValidationError {
    LanguageUnsupported {
        message: String,
    },
    Parse {
        message: String,
    },
    CapBytes {
        message: String,
    },
    CapNesting {
        message: String,
    },
    CapClauses {
        message: String,
    },
    CapCost {
        message: String,
    },
    EngineFault {
        message: String,
    },
    SettingsInvalid {
        message: String,
    },
    ExampleFailed {
        example_name: String,
        message: String,
    },
    EngineUnavailable {
        message: String,
    },
}

impl RuleValidationError {
    /// Only `engine_unavailable` is retryable: authoring failures need a
    /// corrected revision/settings; deterministic engine defects need repair.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::EngineUnavailable { .. })
    }
}

/// Host-side evidence binding: the evidence must echo the request language
/// and both digests, else admission refuses before any append.
pub fn evidence_binds_request(
    evidence: &EngineValidationEvidence,
    revision: &RuleRevision,
    revision_digest: &str,
    settings_digest: &str,
) -> Result<()> {
    if evidence.revision_digest != revision_digest
        || evidence.settings_digest != settings_digest
        || evidence.language_identity != revision.language
    {
        return Err(refuse(
            "engine evidence does not bind the validated revision and settings",
        ));
    }
    Ok(())
}

/// Structural validation of engine evidence metadata: identity, policy, and
/// version are nonempty bounded strings; a present bundle hash must be 64
/// lowercase hex chars. The settings-object rule lives in
/// [`settings_digest`]; digest binding in [`evidence_binds_request`].
pub fn validate_evidence_shape(evidence: &EngineValidationEvidence) -> Result<()> {
    for (kind, value) in [
        ("language identity", &evidence.language_identity),
        ("policy version", &evidence.policy_version),
        ("engine id", &evidence.engine_id),
        ("engine version", &evidence.engine_version),
    ] {
        if value.is_empty() || value.len() > 128 {
            return Err(malformed(format!(
                "engine evidence {kind} must be 1..128 bytes"
            )));
        }
    }
    if let Some(bundle) = &evidence.bundle_sha256 {
        if bundle.len() != 64
            || !bundle
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(malformed(
                "engine evidence bundle must be 64 lowercase hex chars",
            ));
        }
    }
    Ok(())
}

/// Replay verification from stored bytes: shape validity plus recomputed
/// revision/settings digests against the logged pins. No SQL preparation, no
/// catalog, no read-sets, no labels — historical replay never prepares SQL
/// under today's catalog. Admission-time checks (DAG, current catalog) live
/// in [`validate_parameter_dag`] and the writer-transaction rechecks, never
/// here.
pub fn verify_replay_revision(
    revision: &RuleRevision,
    expected_revision: &str,
    settings: &serde_json::Value,
    expected_settings: &str,
) -> Result<()> {
    validate_revision_shape(revision)?;
    if revision_digest(revision)? != expected_revision {
        return Err(refuse(
            "stored rule bytes do not reproduce the logged revision digest",
        ));
    }
    if settings_digest(settings)? != expected_settings {
        return Err(refuse(
            "stored settings do not reproduce the logged settings digest",
        ));
    }
    Ok(())
}

/// Privately constructed persisted payload: only the host builds it at
/// admission (after evidence binding) through [`RuleAdmissionReceipt::issue`],
/// and no registration request accepts evidence or a receipt — that missing
/// request surface is the boundary, not Rust field visibility alone (the
/// derived Deserialize impl stays reachable wherever the type is). Fields
/// stay crate-visible for the later fold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleAdmissionReceipt {
    pub(crate) revision_digest: String,
    pub(crate) settings_digest: String,
    pub(crate) readset_digest: String,
    pub(crate) language_identity: String,
    pub(crate) policy_version: String,
    pub(crate) engine_id: String,
    pub(crate) engine_version: String,
    pub(crate) bundle_sha256: Option<String>,
}

impl RuleAdmissionReceipt {
    /// Bind verified evidence plus the complete read-set digest. Call only
    /// after [`evidence_binds_request`] passes and the writer-transaction
    /// rechecks (authority, ExpectedSeq, catalog/pins/digests) hold.
    pub(crate) fn issue(evidence: EngineValidationEvidence, readset_digest: String) -> Self {
        Self {
            revision_digest: evidence.revision_digest,
            settings_digest: evidence.settings_digest,
            readset_digest,
            language_identity: evidence.language_identity,
            policy_version: evidence.policy_version,
            engine_id: evidence.engine_id,
            engine_version: evidence.engine_version,
            bundle_sha256: evidence.bundle_sha256,
        }
    }
}

/// Test-only fixture engine identity. Non-test paths must refuse evidence
/// carrying it; it can never admit installations.
pub const FIXTURE_ENGINE_ID: &str = "fixture-rule-validator";

/// Whether evidence came from the test-only fixture validator.
pub fn is_fixture_engine_id(engine_id: &str) -> bool {
    engine_id == FIXTURE_ENGINE_ID
}

/// Refuse fixture evidence outside tests: the agreed invariant is that only
/// real engine evidence reaches storage and call paths.
pub fn ensure_non_fixture_evidence(evidence: &EngineValidationEvidence) -> Result<()> {
    if is_fixture_engine_id(&evidence.engine_id) {
        return Err(refuse(
            "fixture validation evidence cannot admit installations",
        ));
    }
    Ok(())
}

/// Receipt-side guard reusing the evidence checks: reconstructs the evidence
/// view from a stored receipt and runs shape + non-fixture validation. The
/// gated fold, keyed reads, and admission all invoke this before using any
/// receipt; the call gate re-checks it on every invocation.
pub fn verify_receipt_usable(receipt: &RuleAdmissionReceipt) -> Result<()> {
    for (kind, digest) in [
        ("revision", &receipt.revision_digest),
        ("settings", &receipt.settings_digest),
        ("read-set", &receipt.readset_digest),
    ] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(malformed(format!(
                "stored receipt {kind} digest must be 64 lowercase hex chars"
            )));
        }
    }
    let evidence = EngineValidationEvidence {
        revision_digest: receipt.revision_digest.clone(),
        settings_digest: receipt.settings_digest.clone(),
        language_identity: receipt.language_identity.clone(),
        policy_version: receipt.policy_version.clone(),
        engine_id: receipt.engine_id.clone(),
        engine_version: receipt.engine_version.clone(),
        bundle_sha256: receipt.bundle_sha256.clone(),
    };
    validate_evidence_shape(&evidence)?;
    ensure_non_fixture_evidence(&evidence)
}

/// Test-only fixture validator (struct AND impl are cfg(test)): in non-test
/// probe builds the type does not exist, so fixture evidence can never be
/// minted there. Detection stays available via [`is_fixture_engine_id`], and
/// non-test paths must refuse it via [`ensure_non_fixture_evidence`]. No
/// claimed real parsing.
#[cfg(test)]
pub struct FixtureValidator;

#[cfg(test)]
impl RuleValidator for FixtureValidator {
    fn validate(
        &self,
        request: RuleValidationRequest<'_>,
    ) -> std::result::Result<EngineValidationEvidence, RuleValidationError> {
        Ok(EngineValidationEvidence {
            revision_digest: request.revision_digest.to_owned(),
            settings_digest: request.settings_digest.to_owned(),
            language_identity: request.revision.language.clone(),
            policy_version: "fixture-policy-0".to_owned(),
            engine_id: FIXTURE_ENGINE_ID.to_owned(),
            engine_version: "0.0.0-fixture".to_owned(),
            bundle_sha256: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use native_query_contract::rule_contract::{PinnedRelation, RuleInputReadset};

    fn sample_revision() -> RuleRevision {
        RuleRevision {
            scalar_arguments: vec![],
            binding_contract: None,
            namespace: "billing".to_owned(),
            name: "overdue".to_owned(),
            language: "cel-subset@1".to_owned(),
            inputs: vec![
                RuleInputDecl {
                    contract: None,
                    name: "deal".to_owned(),
                    sql: "SELECT id, region FROM records WHERE id = ?1".to_owned(),
                    cardinality: RuleCardinality::One,
                    required_fields: vec!["region".to_owned(), "id".to_owned()],
                    parameters: vec![ParameterDecl {
                        slot: 1,
                        param_type: "text".to_owned(),
                        nullable: false,
                        source: ParameterSource::Argument {
                            name: "bid".to_owned(),
                        },
                    }],
                },
                RuleInputDecl {
                    contract: None,
                    name: "policy".to_owned(),
                    sql: "SELECT id FROM records WHERE region = ?1 AND updated_at_ms > ?2"
                        .to_owned(),
                    cardinality: RuleCardinality::Many,
                    required_fields: vec!["id".to_owned()],
                    parameters: vec![
                        ParameterDecl {
                            slot: 1,
                            param_type: "text".to_owned(),
                            nullable: false,
                            source: ParameterSource::InputRow {
                                input: "deal".to_owned(),
                                field: "region".to_owned(),
                            },
                        },
                        ParameterDecl {
                            slot: 2,
                            param_type: "timestamp".to_owned(),
                            nullable: false,
                            source: ParameterSource::NowMs,
                        },
                    ],
                },
            ],
            clauses: "deal.region == policy.region".to_owned(),
            examples: vec![],
            definition_pins: vec![],
        }
    }

    #[test]
    fn revision_digest_is_stable_and_byte_sensitive() {
        let revision = sample_revision();
        let digest = revision_digest(&revision).expect("safe");
        assert_eq!(revision_digest(&revision).expect("safe"), digest);
        // Unordered sets canonicalize: field order never moves the digest.
        let mut reordered = revision.clone();
        reordered.inputs[0].required_fields.reverse();
        assert_eq!(revision_digest(&reordered).expect("safe"), digest);
        // Declaration order never moves the digest either (inputs sort by name).
        let mut swapped = revision.clone();
        swapped.inputs.reverse();
        assert_eq!(revision_digest(&swapped).expect("safe"), digest);
        // Exact bytes matter: one SQL byte mints a new revision.
        let mut touched = revision.clone();
        touched.inputs[0].sql.push(' ');
        assert_ne!(revision_digest(&touched).expect("safe"), digest);
    }

    #[test]
    fn settings_digest_needs_a_json_object() {
        let digest = settings_digest(&serde_json::json!({"level": "advise"})).expect("object");
        assert_eq!(digest.len(), 64);
        assert!(settings_digest(&serde_json::json!([1])).is_err());
        // 2^53 and 2^53+1 refuse (nested too); the boundary and fractions pass.
        assert!(settings_digest(&serde_json::json!({"x": big(9007199254740992)})).is_err());
        assert!(
            settings_digest(&serde_json::json!({"x": {"y": [big(9007199254740993)]}})).is_err()
        );
        assert!(settings_digest(&serde_json::json!({"x": big(9007199254740991)})).is_ok());
        assert!(settings_digest(&serde_json::json!({"x": 1.5})).is_ok());
    }

    #[test]
    fn unsafe_example_numbers_refuse_but_tagged_strings_roundtrip() {
        // 2^53 and 2^53+1 refuse before canonical hashing, nested too. This
        // is the cross-runtime interop policy, not a claim about the pinned
        // formatter (which writes these integers exactly): large values must
        // be tagged strings.
        for body in [
            serde_json::json!(big(9007199254740992)),
            serde_json::json!(big(9007199254740993)),
            serde_json::json!(big(-9007199254740992)),
            serde_json::Value::from(u64::MAX),
            serde_json::json!({"rows": [{"n": big(9007199254740993)}]}),
        ] {
            let mut revision = sample_revision();
            revision.examples.push(RuleExample {
                name: "r9".to_owned(),
                body,
            });
            assert!(validate_revision_shape(&revision).is_err());
            assert!(revision_digest(&revision).is_err());
        }
        // Boundary integers, in-range fractions, and tagged strings pass, and
        // distinct tagged strings stay distinct.
        let mut revision = sample_revision();
        revision.examples.push(RuleExample {
            name: "r9".to_owned(),
            body: serde_json::json!({
                "max": big(9007199254740991), "ratio": 1.5, "big": "9007199254740993",
            }),
        });
        assert!(validate_revision_shape(&revision).is_ok());
        let digest = revision_digest(&revision).expect("safe");
        let mut other = revision.clone();
        other.examples[0].body = serde_json::json!({"max": big(9007199254740991), "ratio": 1.5, "big": "9007199254740994"});
        assert_ne!(revision_digest(&other).expect("safe"), digest);
        // Canonical bytes decode back to the exact tagged strings: 2^53,
        // 2^53+1 and u64::MAX roundtrip as strings, never as numbers.
        let mut tagged = revision.clone();
        tagged.examples[0].body = serde_json::json!({
            "a": "9007199254740992",
            "b": "9007199254740993",
            "c": "18446744073709551615",
        });
        assert!(validate_revision_shape(&tagged).is_ok());
        let bytes = crate::canonical_json::canonical_json(&canonical_revision_value(&tagged));
        let decoded: serde_json::Value =
            serde_json::from_slice(&bytes).expect("canonical bytes decode");
        let body = &decoded["examples"][0]["body"];
        assert_eq!(body["a"], serde_json::json!("9007199254740992"));
        assert_eq!(body["b"], serde_json::json!("9007199254740993"));
        assert_eq!(body["c"], serde_json::json!("18446744073709551615"));
    }

    #[test]
    fn revision_shape_rejects_bad_tokens_and_empties() {
        assert!(validate_revision_shape(&sample_revision()).is_ok());
        let mut revision = sample_revision();
        revision.language = "cel subset!".to_owned();
        assert!(validate_revision_shape(&revision).is_err());
        revision = sample_revision();
        revision.clauses.clear();
        assert!(validate_revision_shape(&revision).is_err());
        revision = sample_revision();
        revision.inputs[1].name = "deal".to_owned();
        assert!(validate_revision_shape(&revision).is_err());
        revision = sample_revision();
        revision.inputs[0].parameters[0].param_type = "frob".to_owned();
        assert!(validate_revision_shape(&revision).is_err());
        // v0 pins are preserved (existing identity semantics: no invented
        // zero-version refusal); duplicate families refuse.
        let mut v0 = sample_revision();
        v0.definition_pins.push(DefinitionPin {
            family: "k".to_owned(),
            version: 0,
            digest: "a".repeat(64),
        });
        assert!(validate_revision_shape(&v0).is_ok());
        v0.definition_pins.push(DefinitionPin {
            family: "k".to_owned(),
            version: 1,
            digest: "b".repeat(64),
        });
        assert!(validate_revision_shape(&v0).is_err());
    }

    #[test]
    fn duplicate_parameter_slots_refuse_in_shape() {
        let mut revision = sample_revision();
        revision.inputs[0].parameters.push(ParameterDecl {
            slot: 1,
            param_type: "text".to_owned(),
            nullable: false,
            source: ParameterSource::Argument {
                name: "bid".to_owned(),
            },
        });
        assert!(validate_revision_shape(&revision).is_err());
    }

    fn sample_readsets() -> BTreeMap<String, RuleInputReadset> {
        BTreeMap::from([
            (
                "deal".to_owned(),
                RuleInputReadset {
                    relations: vec![PinnedRelation {
                        identity: "native.query-sql.records".to_owned(),
                        name: "records".to_owned(),
                        semantic_version: 1,
                        columns: ["id", "region"].iter().map(|s| s.to_string()).collect(),
                        population_only: false,
                    }],
                    parameter_slots: vec![1],
                    uses_now_ms: false,
                },
            ),
            (
                "policy".to_owned(),
                RuleInputReadset {
                    relations: vec![PinnedRelation {
                        identity: "native.query-sql.records".to_owned(),
                        name: "records".to_owned(),
                        semantic_version: 1,
                        columns: ["id", "region", "updated_at_ms"]
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                        population_only: false,
                    }],
                    parameter_slots: vec![1, 2],
                    uses_now_ms: false,
                },
            ),
        ])
    }

    /// Exact i64 JSON number (json! would default the literal to i32).
    fn big(int: i64) -> serde_json::Value {
        serde_json::Value::from(int)
    }

    fn sample_labels() -> BTreeMap<String, Vec<String>> {
        BTreeMap::from([
            (
                "deal".to_owned(),
                vec!["id".to_owned(), "region".to_owned()],
            ),
            ("policy".to_owned(), vec!["id".to_owned()]),
        ])
    }

    #[test]
    fn parameter_dag_accepts_valid_graph_and_rejects_breaks() {
        let revision = sample_revision();
        let order =
            validate_parameter_dag(&revision, &sample_readsets(), &sample_labels()).expect("valid");
        assert_eq!(order, vec!["deal".to_owned(), "policy".to_owned()]);
        // Declared slots must exactly match the authoritative slots.
        let mut revision = sample_revision();
        revision.inputs[1].parameters[1].slot = 3;
        assert!(validate_parameter_dag(&revision, &sample_readsets(), &sample_labels()).is_err());
        // Required fields must sit among the validated output labels.
        let mut revision = sample_revision();
        revision.inputs[0].required_fields.push("gone".to_owned());
        assert!(validate_parameter_dag(&revision, &sample_readsets(), &sample_labels()).is_err());
        // Row sources must point backwards at one-row inputs with real fields.
        let mut later = sample_revision();
        later.inputs[0].parameters.push(ParameterDecl {
            slot: 2,
            param_type: "text".to_owned(),
            nullable: false,
            source: ParameterSource::InputRow {
                input: "policy".to_owned(),
                field: "id".to_owned(),
            },
        });
        // Widen the derived slots so the backwards-edge rule itself fires.
        let mut later_readsets = sample_readsets();
        later_readsets
            .get_mut("deal")
            .expect("present")
            .parameter_slots = vec![1, 2];
        assert!(validate_parameter_dag(&later, &later_readsets, &sample_labels()).is_err());
        // Unknown source inputs and unknown source fields refuse.
        let mut unknown = sample_revision();
        unknown.inputs[1].parameters[0].source = ParameterSource::InputRow {
            input: "missing".to_owned(),
            field: "id".to_owned(),
        };
        assert!(validate_parameter_dag(&unknown, &sample_readsets(), &sample_labels()).is_err());
        let mut bad_field = sample_revision();
        bad_field.inputs[1].parameters[0].source = ParameterSource::InputRow {
            input: "deal".to_owned(),
            field: "gone".to_owned(),
        };
        assert!(validate_parameter_dag(&bad_field, &sample_readsets(), &sample_labels()).is_err());
        let mut many = sample_revision();
        many.inputs.push(RuleInputDecl {
            contract: None,
            name: "third".to_owned(),
            sql: "SELECT id FROM records WHERE id = ?1".to_owned(),
            cardinality: RuleCardinality::One,
            required_fields: vec![],
            parameters: vec![ParameterDecl {
                slot: 1,
                param_type: "text".to_owned(),
                nullable: false,
                source: ParameterSource::InputRow {
                    input: "policy".to_owned(),
                    field: "id".to_owned(),
                },
            }],
        });
        let mut readsets = sample_readsets();
        readsets.insert(
            "third".to_owned(),
            RuleInputReadset {
                relations: vec![],
                parameter_slots: vec![1],
                uses_now_ms: false,
            },
        );
        let mut labels = sample_labels();
        labels.insert("third".to_owned(), vec!["id".to_owned()]);
        assert!(validate_parameter_dag(&many, &readsets, &labels).is_err());
    }

    #[test]
    fn parameter_dag_orders_forward_refs_and_reports_cycles() {
        let one = |name: &str, sql: &str, cardinality: RuleCardinality| RuleInputDecl {
            contract: None,
            name: name.to_owned(),
            sql: sql.to_owned(),
            cardinality,
            required_fields: vec![],
            parameters: vec![],
        };
        let mut revision = sample_revision();
        // Declared [later, early]: the forward ref is accepted, order derived.
        revision.inputs = vec![
            one(
                "later",
                "SELECT id FROM records WHERE region = ?1 AND kind = ?2",
                RuleCardinality::One,
            ),
            one(
                "early",
                "SELECT region, kind FROM records",
                RuleCardinality::One,
            ),
        ];
        revision.inputs[0].parameters = vec![
            ParameterDecl {
                slot: 1,
                param_type: "text".to_owned(),
                nullable: false,
                source: ParameterSource::InputRow {
                    input: "early".to_owned(),
                    field: "region".to_owned(),
                },
            },
            ParameterDecl {
                slot: 2,
                param_type: "text".to_owned(),
                nullable: false,
                source: ParameterSource::InputRow {
                    input: "early".to_owned(),
                    field: "kind".to_owned(),
                },
            },
        ];
        let readsets = BTreeMap::from([
            (
                "later".to_owned(),
                RuleInputReadset {
                    relations: vec![],
                    parameter_slots: vec![1, 2],
                    uses_now_ms: false,
                },
            ),
            (
                "early".to_owned(),
                RuleInputReadset {
                    relations: vec![],
                    parameter_slots: vec![],
                    uses_now_ms: false,
                },
            ),
        ]);
        let labels = BTreeMap::from([
            ("later".to_owned(), vec!["id".to_owned()]),
            (
                "early".to_owned(),
                vec!["region".to_owned(), "kind".to_owned()],
            ),
        ]);
        // Duplicate edges (two fields, one source) share one indegree unit.
        let order = validate_parameter_dag(&revision, &readsets, &labels).expect("acyclic");
        assert_eq!(order, vec!["early".to_owned(), "later".to_owned()]);
        // A back edge closes a genuine cycle and refuses.
        revision.inputs[1].parameters.push(ParameterDecl {
            slot: 1,
            param_type: "text".to_owned(),
            nullable: false,
            source: ParameterSource::InputRow {
                input: "later".to_owned(),
                field: "id".to_owned(),
            },
        });
        let mut cyclic_readsets = readsets.clone();
        cyclic_readsets
            .get_mut("early")
            .expect("present")
            .parameter_slots = vec![1];
        assert!(validate_parameter_dag(&revision, &cyclic_readsets, &labels).is_err());
    }

    #[test]
    fn parameter_dag_enforces_argument_coherence() {
        let mut revision = sample_revision();
        // policy ?2 reuses deal's `bid` argument with a conflicting type.
        revision.inputs[1].parameters[1].source = ParameterSource::Argument {
            name: "bid".to_owned(),
        };
        assert!(validate_parameter_dag(&revision, &sample_readsets(), &sample_labels()).is_err());
        // Same name and same type is coherent and keeps working.
        revision.inputs[1].parameters[1].param_type = "text".to_owned();
        let order = validate_parameter_dag(&revision, &sample_readsets(), &sample_labels())
            .expect("coherent");
        assert_eq!(order, vec!["deal".to_owned(), "policy".to_owned()]);
    }

    #[test]
    fn evidence_must_bind_request_and_fixture_stays_test_only() {
        let revision = sample_revision();
        let revision_digest = revision_digest(&revision).expect("safe sample");
        let settings = serde_json::json!({"level": "advise"});
        let settings_digest = settings_digest(&settings).expect("object");
        let request = RuleValidationRequest {
            revision: &revision,
            settings: &settings,
            revision_digest: &revision_digest,
            settings_digest: &settings_digest,
        };
        let evidence = FixtureValidator.validate(request).expect("fixture passes");
        assert!(
            evidence_binds_request(&evidence, &revision, &revision_digest, &settings_digest)
                .is_ok()
        );
        let mut tampered = evidence.clone();
        tampered.settings_digest = "0".repeat(64);
        assert!(
            evidence_binds_request(&tampered, &revision, &revision_digest, &settings_digest)
                .is_err()
        );
        // Fixture identity is detectable so non-test paths can refuse it.
        assert!(is_fixture_engine_id(&evidence.engine_id));
        assert!(!is_fixture_engine_id("cel-engine"));
        // The host-issued receipt binds evidence plus the read-set digest.
        let receipt = RuleAdmissionReceipt::issue(evidence, "readset-digest".to_owned());
        assert_eq!(receipt.revision_digest, revision_digest);
        assert_eq!(receipt.readset_digest, "readset-digest");
        assert_eq!(receipt.engine_id, FIXTURE_ENGINE_ID);
    }

    #[test]
    fn evidence_shape_and_replay_verify() {
        let revision = sample_revision();
        let revision_digest = revision_digest(&revision).expect("safe sample");
        let settings = serde_json::json!({"level": "advise"});
        let settings_digest = settings_digest(&settings).expect("object");
        let evidence = EngineValidationEvidence {
            revision_digest: revision_digest.clone(),
            settings_digest: settings_digest.clone(),
            language_identity: "cel-subset@1".to_owned(),
            policy_version: "g3-1".to_owned(),
            engine_id: "cel-engine".to_owned(),
            engine_version: "1.2.3".to_owned(),
            bundle_sha256: Some("a".repeat(64)),
        };
        assert!(validate_evidence_shape(&evidence).is_ok());
        assert!(ensure_non_fixture_evidence(&evidence).is_ok());
        assert!(
            verify_replay_revision(&revision, &revision_digest, &settings, &settings_digest)
                .is_ok()
        );
        let mut empty = evidence.clone();
        empty.engine_id.clear();
        assert!(validate_evidence_shape(&empty).is_err());
        let mut bad_bundle = evidence.clone();
        bad_bundle.bundle_sha256 = Some("xyz".to_owned());
        assert!(validate_evidence_shape(&bad_bundle).is_err());
        let mut tampered = revision.clone();
        tampered.clauses.push(';');
        assert!(
            verify_replay_revision(&tampered, &revision_digest, &settings, &settings_digest)
                .is_err()
        );
    }

    #[test]
    fn engine_unavailable_is_the_only_retryable_code() {
        let retryable = RuleValidationError::EngineUnavailable {
            message: "busy".to_owned(),
        };
        assert!(retryable.is_retryable());
        for author in [
            RuleValidationError::LanguageUnsupported {
                message: "m".to_owned(),
            },
            RuleValidationError::Parse {
                message: "m".to_owned(),
            },
            RuleValidationError::CapBytes {
                message: "m".to_owned(),
            },
            RuleValidationError::CapNesting {
                message: "m".to_owned(),
            },
            RuleValidationError::CapClauses {
                message: "m".to_owned(),
            },
            RuleValidationError::CapCost {
                message: "m".to_owned(),
            },
            RuleValidationError::EngineFault {
                message: "m".to_owned(),
            },
            RuleValidationError::SettingsInvalid {
                message: "m".to_owned(),
            },
            RuleValidationError::ExampleFailed {
                example_name: "r9".to_owned(),
                message: "m".to_owned(),
            },
        ] {
            assert!(!author.is_retryable());
        }
    }

    #[test]
    fn receipt_guard_refuses_fixture_but_allows_real() {
        let real = RuleAdmissionReceipt {
            revision_digest: "a".repeat(64),
            settings_digest: "b".repeat(64),
            readset_digest: "c".repeat(64),
            language_identity: "cel-subset@1".to_owned(),
            policy_version: "g3-1".to_owned(),
            engine_id: "cel-engine".to_owned(),
            engine_version: "1.2.3".to_owned(),
            bundle_sha256: None,
        };
        assert!(verify_receipt_usable(&real).is_ok());
        let mut reserved = real.clone();
        reserved.engine_id = FIXTURE_ENGINE_ID.to_owned();
        assert!(verify_receipt_usable(&reserved).is_err());
        let mut malformed = real.clone();
        malformed.readset_digest.clear();
        assert!(verify_receipt_usable(&malformed).is_err());
    }

    #[test]
    fn readset_digest_binds_complete_evidence() {
        let readsets = sample_readsets();
        let pairs: Vec<(&str, &RuleInputReadset)> =
            vec![("policy", &readsets["policy"]), ("deal", &readsets["deal"])];
        let digest = readset_digest(4, "sqlite-local", 1, &pairs);
        assert_eq!(digest.len(), 64);
        // Caller order never moves the digest; a catalog bump does.
        let swapped: Vec<(&str, &RuleInputReadset)> =
            vec![("deal", &readsets["deal"]), ("policy", &readsets["policy"])];
        assert_eq!(readset_digest(4, "sqlite-local", 1, &swapped), digest);
        assert_ne!(readset_digest(5, "sqlite-local", 1, &pairs), digest);
    }
}
