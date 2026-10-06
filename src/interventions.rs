//! Policy-gated Message sends and Message-rooted human interventions.
//!
//! This first slice deliberately reuses portable standing-instruction bindings
//! as the authority/versioning layer for principal policy sources.  A bound
//! `Document kind:escalation-policy` contains the closed JSON contract below;
//! the compiler never interprets arbitrary instruction prose as policy.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, Transaction};

use crate::authorization::{self, Capability, Principal};
use crate::error::{Error, Result};
use crate::mcp::Caller;

pub const POLICY_FORMAT: &str = "native.escalation-policy.v1";
pub const TRACE_FORMAT: &str = "native.escalation-policy-trace.v1";
pub const VIEW_FORMAT: &str = "native.intervention-view.v1";
pub const DEFAULT_DISPOSITION: &str = "notify_and_proceed";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    format: String,
    issuer_principal_id: String,
    statements: Vec<PolicyStatement>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyStatement {
    statement_id: String,
    kind: String,
    #[serde(default)]
    scope: BTreeMap<String, Vec<Value>>,
    #[serde(default)]
    when: Option<PredicateGroup>,
    #[serde(default)]
    effect: Option<PolicyEffect>,
    #[serde(default)]
    guidance: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PredicateGroup {
    all: Vec<Predicate>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Predicate {
    field: String,
    op: String,
    #[serde(default)]
    value: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyEffect {
    disposition: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyEvaluation {
    pub disposition: String,
    pub action: Value,
    pub trace: Value,
    pub evaluation_digest: String,
    pub action_digest: String,
    pub context_digest: String,
    pub compiled_policy_digest: String,
}

#[derive(Debug, Clone)]
struct Source {
    binding_id: String,
    scope: String,
    source_record_id: String,
    source_digest: String,
    document: PolicyDocument,
}

pub fn sha256_json(value: &Value) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

pub fn evaluation_digest_for_trace(trace: &Value) -> Result<String> {
    if trace.get("format").and_then(Value::as_str) != Some(TRACE_FORMAT) {
        return Err(Error::engine("invalid escalation policy trace format"));
    }
    let mut normalized = trace.clone();
    let object = normalized
        .as_object_mut()
        .ok_or_else(|| Error::engine("escalation policy trace must be an object"))?;
    object.insert("evaluation_digest".into(), Value::String("pending".into()));
    sha256_json(&normalized)
}

pub fn verify_evaluation_trace(trace: &Value, expected_digest: &str) -> Result<()> {
    let embedded = trace
        .get("evaluation_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::engine("escalation policy trace has no evaluation_digest"))?;
    let recomputed = evaluation_digest_for_trace(trace)?;
    if embedded != expected_digest || recomputed != expected_digest {
        return Err(Error::engine(
            "escalation policy trace evaluation digest mismatch",
        ));
    }
    Ok(())
}

/// The stand-in a non-owner response carries where an unreadable policy
/// source's identifier would otherwise appear. It is a fixed string so a fresh
/// response and an idempotent retry of the same persisted trace render
/// byte-identically.
pub const REDACTED_POLICY_SOURCE_ID: &str = "redacted:policy-source-unreadable";

/// Record ids of every policy source named anywhere in a trace: the admitted
/// `sources` list and every conflict item. Readability is tested against these
/// record ids; a binding id is not a record id and is collected by
/// [`collect_hidden_identifiers`] once its source is known to be hidden.
fn policy_source_record_ids(trace: &Value) -> Vec<String> {
    fn walk(value: &Value, ids: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for key in ["record_id", "source_record_id"] {
                    if let Some(id) = map.get(key).and_then(Value::as_str) {
                        if !ids.iter().any(|seen| seen == id) {
                            ids.push(id.to_string());
                        }
                    }
                }
                for child in map.values() {
                    walk(child, ids);
                }
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, ids);
                }
            }
            _ => {}
        }
    }
    let mut ids = Vec::new();
    walk(trace, &mut ids);
    ids
}

fn push_unique(out: &mut Vec<String>, text: &str) {
    if !out.iter().any(|seen| seen == text) {
        out.push(text.to_string());
    }
}

/// Every identifier the trace keeps beside a source whose record id is hidden:
/// its binding id, source digest, issuer principal id, and statement ids. A
/// reader who cannot name the source cannot hold any of its descriptors either.
/// Walked recursively from objects that carry a hidden `record_id` /
/// `source_record_id`.
fn collect_hidden_identifiers(value: &Value, hidden: &[String], out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            let source_hidden = ["record_id", "source_record_id"].iter().any(|key| {
                map.get(*key)
                    .and_then(Value::as_str)
                    .is_some_and(|id| hidden.iter().any(|hidden_id| hidden_id == id))
            });
            if source_hidden {
                for key in ["binding_id", "source_digest", "issuer_principal_id"] {
                    if let Some(text) = map.get(key).and_then(Value::as_str) {
                        push_unique(out, text);
                    }
                }
                if let Some(statement) = map.get("statement_id").and_then(Value::as_str) {
                    push_unique(out, statement);
                }
                if let Some(statements) = map.get("statement_ids").and_then(Value::as_array) {
                    for statement in statements.iter().filter_map(Value::as_str) {
                        push_unique(out, statement);
                    }
                }
            }
            for child in map.values() {
                collect_hidden_identifiers(child, hidden, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_hidden_identifiers(item, hidden, out);
            }
        }
        _ => {}
    }
}

/// Apply the replacement for a known-hidden record-id set. The pure core of
/// [`redact_trace_for_caller`], kept separately testable.
fn redact_trace_with_hidden(trace: &Value, hidden_record_ids: &[String]) -> Value {
    if hidden_record_ids.is_empty() {
        return trace.clone();
    }
    let mut identifiers = hidden_record_ids.to_vec();
    collect_hidden_identifiers(trace, hidden_record_ids, &mut identifiers);
    let mut redacted = trace.clone();
    redact_policy_source_ids(&mut redacted, &identifiers);
    redacted
}

/// Replace every exact occurrence of a hidden identifier anywhere in `value`.
/// The trace's shape, conflicts, disposition and digests are otherwise
/// preserved; only the caller-facing clone is touched.
fn redact_policy_source_ids(value: &mut Value, hidden: &[String]) {
    match value {
        Value::String(text) => {
            if hidden.iter().any(|identifier| identifier == text) {
                *text = REDACTED_POLICY_SOURCE_ID.to_string();
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_policy_source_ids(item, hidden);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                redact_policy_source_ids(item, hidden);
            }
        }
        _ => {}
    }
}

/// The policy trace as `caller` may see it, evaluated against the caller's
/// **current** readability. A host owner — the same footing `require_owner`
/// gates on — keeps the full trace. Everyone else has every identifier of a
/// policy source they cannot View now replaced by
/// [`REDACTED_POLICY_SOURCE_ID`]; the disposition, the conflicts and the
/// digests are untouched.
///
/// Readability is re-checked here rather than trusted from the trace's own
/// `policy_source_unreadable` entries, because the idempotent-retry path
/// returns a trace evaluated under earlier capabilities: a source the sender
/// could View at the first send may since have been revoked, and the retry
/// must not name it.
///
/// Residual (accepted): the returned `evaluation_digest` (and the intervention
/// view's `trace_digest`) is SHA-256 over the *unredacted* trace, so someone
/// who already knows a hidden source's random id — or a low-entropy
/// caller-supplied binding id — could confirm a guess by recomputing it. We
/// deliberately do not change digest inputs: that digest is the resume
/// compare-and-swap guard (`mcp/tools/interventions.rs` view and
/// `resume_delivery`), so it must stay identical to the persisted value.
/// Closing the residual needs a digest of the redacted trace computed
/// consistently in both the view and `resume_delivery`; that is a separate
/// change.
pub async fn redact_trace_for_caller(
    db: &crate::db::Db,
    caller: &Caller,
    trace: &Value,
) -> Result<Value> {
    if caller.is_host_owner() {
        return Ok(trace.clone());
    }
    let principal = Principal::bound(caller.credential(), caller.is_host_member());
    let mut hidden = Vec::new();
    for record_id in policy_source_record_ids(trace) {
        let viewable = authorization::effective_capability(db, principal, &record_id)
            .await
            .map(|capability| capability.allows(Capability::View))
            .unwrap_or(false);
        if !viewable && !hidden.iter().any(|seen| seen == &record_id) {
            hidden.push(record_id);
        }
    }
    Ok(redact_trace_with_hidden(trace, &hidden))
}

pub fn canonical_route(database_id: &str, intervention_id: &str) -> String {
    let encode = |value: &str| {
        percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
    };
    format!(
        "/workbench/databases/{}/interventions/{}",
        encode(database_id),
        encode(intervention_id)
    )
}

pub async fn database_id_in(tx: &mut Transaction<'_, Sqlite>) -> Result<String> {
    sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
        .fetch_one(&mut **tx)
        .await
        .map_err(Into::into)
}

async fn sources_in(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
) -> Result<(Vec<Source>, Vec<Value>)> {
    let rows = sqlx::query(
        "SELECT b.id binding_id,b.scope_kind,b.scope_id,b.source_record_id,
                r.body,r.owner_id,r.updated_at,
                (SELECT identifier FROM bindings
                  WHERE record_id=r.owner_id AND system='native-principal' AND is_canonical=1)
                  owner_principal
           FROM instruction_bindings b
           JOIN records r ON r.id=b.source_record_id
          WHERE b.enabled=1 AND r.deleted_at IS NULL
            AND r.type='Document' AND r.kind='escalation-policy'
            AND ((b.scope_kind='database' AND b.scope_id='native:database')
              OR (b.scope_kind='account' AND b.scope_id=?))
          ORDER BY CASE b.scope_kind WHEN 'database' THEN 0 ELSE 1 END,b.position,b.id",
    )
    .bind(caller.credential())
    .fetch_all(&mut **tx)
    .await?;
    let mut sources = Vec::new();
    let mut invalid = Vec::new();
    for row in rows {
        let binding_id: String = row.try_get("binding_id")?;
        let source_record_id: String = row.try_get("source_record_id")?;
        let readable = authorization::effective_capability_on(
            tx,
            Principal::bound(caller.credential(), caller.is_host_member()),
            &source_record_id,
        )
        .await
        .map(|capability| capability.allows(Capability::View))
        .unwrap_or(false);
        if !readable {
            invalid.push(json!({"binding_id":binding_id,"source_record_id":source_record_id,"code":"policy_source_unreadable"}));
            continue;
        }
        let body: Option<String> = row.try_get("body")?;
        let Some(body) = body else {
            invalid.push(json!({"binding_id":binding_id,"source_record_id":source_record_id,"code":"empty_policy_source"}));
            continue;
        };
        let source_digest = hex::encode(Sha256::digest(body.as_bytes()));
        let document: PolicyDocument = match serde_json::from_str(&body) {
            Ok(document) => document,
            Err(error) => {
                invalid.push(json!({"binding_id":binding_id,"source_record_id":source_record_id,"source_digest":source_digest,"code":"invalid_policy_json","detail":error.to_string()}));
                continue;
            }
        };
        let owner_principal: Option<String> = row.try_get("owner_principal")?;
        if document.format != POLICY_FORMAT
            || document.issuer_principal_id.trim().is_empty()
            || owner_principal.as_deref() != Some(document.issuer_principal_id.as_str())
        {
            invalid.push(json!({"binding_id":binding_id,"source_record_id":source_record_id,"source_digest":source_digest,"code":"issuer_authority_mismatch"}));
            continue;
        }
        if document.statements.is_empty() {
            invalid.push(json!({"binding_id":binding_id,"source_record_id":source_record_id,"source_digest":source_digest,"code":"empty_policy_statements"}));
            continue;
        }
        let scope_kind: String = row.try_get("scope_kind")?;
        sources.push(Source {
            binding_id,
            scope: if scope_kind == "database" {
                "workspace"
            } else {
                "member"
            }
            .into(),
            source_record_id,
            source_digest,
            document,
        });
    }
    Ok((sources, invalid))
}

fn fact<'a>(context: &'a Value, field: &str) -> Option<&'a Value> {
    let (head, tail) = field.split_once('.')?;
    context.get(head)?.get(tail)
}

fn values_overlap(actual: &Value, allowed: &[Value]) -> bool {
    match actual {
        Value::Array(values) => values.iter().any(|value| allowed.contains(value)),
        value => allowed.contains(value),
    }
}

fn scope_matches(scope: &BTreeMap<String, Vec<Value>>, context: &Value) -> bool {
    scope.iter().all(|(field, allowed)| {
        !allowed.is_empty()
            && fact(context, field).is_some_and(|actual| values_overlap(actual, allowed))
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PolicyFieldKind {
    Identifier,
    ClosedString(&'static str),
    Boolean,
    IdentifierList,
}

fn policy_field_kind(field: &str) -> Result<PolicyFieldKind> {
    if matches!(field, "agent.id" | "task.id") {
        return Err(Error::engine(format!(
            "unverifiable policy selector '{field}' is not an authenticated registry fact"
        )));
    }
    match field {
        "message.sender_principal_id"
        | "message.workspace_id"
        | "action.destination_workspace_id" => Ok(PolicyFieldKind::Identifier),
        "action.class" => Ok(PolicyFieldKind::ClosedString("communicate")),
        "action.operation" => Ok(PolicyFieldKind::ClosedString("send_message")),
        "action.destination_kind" => Ok(PolicyFieldKind::ClosedString("same_workspace")),
        "action.sensitivity" => Ok(PolicyFieldKind::ClosedString("unknown")),
        "action.reversible" => Ok(PolicyFieldKind::Boolean),
        "action.correspondent_principal_ids" => Ok(PolicyFieldKind::IdentifierList),
        _ => Err(Error::engine(format!(
            "unsupported escalation policy field '{field}'"
        ))),
    }
}

fn value_matches_field(kind: PolicyFieldKind, value: &Value) -> bool {
    match kind {
        PolicyFieldKind::Identifier | PolicyFieldKind::IdentifierList => value
            .as_str()
            .is_some_and(|value| !value.trim().is_empty() && value.chars().count() <= 512),
        PolicyFieldKind::ClosedString(expected) => value.as_str() == Some(expected),
        PolicyFieldKind::Boolean => value.is_boolean(),
    }
}

fn validate_statement(statement: &PolicyStatement) -> Result<()> {
    for (field, allowed) in &statement.scope {
        let kind = policy_field_kind(field)?;
        if allowed.is_empty()
            || allowed
                .iter()
                .any(|value| !value_matches_field(kind, value))
        {
            return Err(Error::engine(format!(
                "scope '{field}' contains values incompatible with that field's closed type"
            )));
        }
    }
    if let Some(group) = &statement.when {
        if group.all.is_empty() {
            return Err(Error::engine(
                "escalation predicate group must not be empty",
            ));
        }
        for predicate in &group.all {
            let kind = policy_field_kind(&predicate.field)?;
            match (kind, predicate.op.as_str()) {
                (_, "exists") if predicate.value.is_null() => {}
                (PolicyFieldKind::IdentifierList, "contains")
                    if value_matches_field(PolicyFieldKind::Identifier, &predicate.value) => {}
                (PolicyFieldKind::IdentifierList, "overlaps")
                    if predicate.value.as_array().is_some_and(|values| {
                        !values.is_empty()
                            && values.iter().all(|value| {
                                value_matches_field(PolicyFieldKind::Identifier, value)
                            })
                    }) => {}
                (PolicyFieldKind::IdentifierList, "contains" | "overlaps") => {
                    return Err(Error::engine(format!(
                        "invalid membership value for escalation predicate '{}' operator '{}'",
                        predicate.field, predicate.op
                    )))
                }
                (PolicyFieldKind::IdentifierList, _) => {
                    return Err(Error::engine(format!(
                        "operator '{}' is incompatible with list field '{}'",
                        predicate.op, predicate.field
                    )))
                }
                (_, "eq") if value_matches_field(kind, &predicate.value) => {}
                (_, "in")
                    if predicate.value.as_array().is_some_and(|values| {
                        !values.is_empty()
                            && values.iter().all(|value| value_matches_field(kind, value))
                    }) => {}
                (_, "exists" | "eq" | "in") => {
                    return Err(Error::engine(format!(
                        "value for escalation predicate '{}' operator '{}' is incompatible with that field's closed type",
                        predicate.field, predicate.op
                    )))
                }
                (_, other) => {
                    return Err(Error::engine(format!(
                        "unsupported escalation predicate operator '{other}'"
                    )))
                }
            }
        }
    }
    let disposition = statement
        .effect
        .as_ref()
        .map(|effect| effect.disposition.as_str());
    match statement.kind.as_str() {
        "hard_rule"
            if statement.when.is_some()
                && disposition.is_some_and(valid_disposition)
                && statement.guidance.is_none() => {}
        "default"
            if statement.when.is_none()
                && disposition.is_some_and(valid_disposition)
                && statement.guidance.is_none() => {}
        "judgment_clause"
            if statement.effect.is_none()
                && statement
                    .guidance
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty()) => {}
        "hard_rule" | "default" | "judgment_clause" => {
            return Err(Error::engine(format!(
                "malformed {} statement",
                statement.kind
            )))
        }
        other => {
            return Err(Error::engine(format!(
                "unknown escalation statement kind '{other}'"
            )))
        }
    }
    Ok(())
}

fn predicate_matches(predicate: &Predicate, context: &Value) -> Result<bool> {
    let actual = fact(context, &predicate.field);
    Ok(match predicate.op.as_str() {
        "exists" => actual.is_some_and(|value| !value.is_null()),
        "eq" => actual == Some(&predicate.value),
        "in" => predicate
            .value
            .as_array()
            .is_some_and(|allowed| actual.is_some_and(|value| values_overlap(value, allowed))),
        "contains" => actual
            .and_then(Value::as_array)
            .is_some_and(|values| values.contains(&predicate.value)),
        "overlaps" => predicate.value.as_array().is_some_and(|allowed| {
            actual
                .and_then(Value::as_array)
                .is_some_and(|values| values.iter().any(|value| allowed.contains(value)))
        }),
        _ => unreachable!("policy predicates are validated before matching"),
    })
}

fn statement_matches(statement: &PolicyStatement, context: &Value) -> Result<bool> {
    if !scope_matches(&statement.scope, context) {
        return Ok(false);
    }
    match &statement.when {
        Some(group) if group.all.is_empty() => Err(Error::engine(
            "escalation hard/judgment predicate group must not be empty",
        )),
        Some(group) => group.all.iter().try_fold(true, |matched, predicate| {
            Ok(matched && predicate_matches(predicate, context)?)
        }),
        None => Ok(true),
    }
}

fn valid_disposition(value: &str) -> bool {
    matches!(
        value,
        "silent_autonomy" | "log_only" | "notify_and_proceed" | "block_and_request_authority"
    )
}

/// Compile principal policy against registry-derived facts.  There is no model
/// evaluator in this slice: matching judgment clauses are reported, then the
/// active default is used.  That omission is fail-safe and explicit in trace.
pub async fn evaluate_in(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    sender_principal: &str,
    correspondent_principals: &[String],
    disclosure_preview: Option<&str>,
) -> Result<PolicyEvaluation> {
    let database_id = database_id_in(tx).await?;
    let context = json!({
        "format":"native.escalation-context.v1",
        "message":{"sender_principal_id":sender_principal,"workspace_id":database_id},
        "action":{
            "class":"communicate",
            "operation":"send_message",
            "destination_kind":"same_workspace",
            "destination_workspace_id":database_id,
            "reversible":false,
            // This value is deliberately not inferred from unrestricted prose.
            "sensitivity":"unknown",
            "correspondent_principal_ids":correspondent_principals,
            "disclosure_preview":disclosure_preview,
        }
    });
    let context_digest = sha256_json(&context)?;
    let action = context.get("action").expect("action exists").clone();
    let action_digest = sha256_json(&action)?;
    let (sources, invalid_sources) = sources_in(tx, caller).await?;
    let compiled_sources = sources
        .iter()
        .map(|source| json!({
            "binding_id":source.binding_id,
            "record_id":source.source_record_id,
            "source_digest":source.source_digest,
            "scope":source.scope,
            "issuer_principal_id":source.document.issuer_principal_id,
            "statement_ids":source.document.statements.iter().map(|statement|statement.statement_id.clone()).collect::<Vec<_>>()
        }))
        .collect::<Vec<_>>();
    let compiled_policy_digest = sha256_json(&json!({
        "format":POLICY_FORMAT,
        "sources":compiled_sources,
    }))?;
    let mut matched_hard_rules = Vec::new();
    let mut hard_outcomes = BTreeSet::new();
    let mut matched_defaults = Vec::new();
    let mut default_outcomes = BTreeSet::new();
    let mut matched_judgment_clauses = Vec::new();
    let mut invalid_statements = invalid_sources;
    let mut seen_ids = BTreeSet::new();
    for source in &sources {
        for statement in &source.document.statements {
            if statement.statement_id.trim().is_empty()
                || !seen_ids.insert(statement.statement_id.clone())
            {
                invalid_statements.push(json!({"source_record_id":source.source_record_id,"statement_id":statement.statement_id,"code":"invalid_or_duplicate_statement_id"}));
                continue;
            }
            if let Err(error) = validate_statement(statement) {
                invalid_statements.push(json!({"source_record_id":source.source_record_id,"statement_id":statement.statement_id,"code":"invalid_statement","detail":error.to_string()}));
                continue;
            }
            let matches = match statement_matches(statement, &context) {
                Ok(matches) => matches,
                Err(error) => {
                    invalid_statements.push(json!({"source_record_id":source.source_record_id,"statement_id":statement.statement_id,"code":"invalid_statement","detail":error.to_string()}));
                    continue;
                }
            };
            if !matches {
                continue;
            }
            match statement.kind.as_str() {
                "hard_rule" => {
                    let disposition = statement.effect.as_ref().map(|effect| effect.disposition.as_str());
                    if statement.when.is_none() || disposition.is_none_or(|value| !valid_disposition(value)) || statement.guidance.is_some() {
                        invalid_statements.push(json!({"source_record_id":source.source_record_id,"statement_id":statement.statement_id,"code":"invalid_hard_rule"}));
                    } else {
                        let disposition = disposition.expect("checked").to_string();
                        hard_outcomes.insert(disposition.clone());
                        matched_hard_rules.push(json!({"statement_id":statement.statement_id,"source_record_id":source.source_record_id,"disposition":disposition}));
                    }
                }
                "default" => {
                    let disposition = statement.effect.as_ref().map(|effect| effect.disposition.as_str());
                    if statement.when.is_some() || disposition.is_none_or(|value| !valid_disposition(value)) || statement.guidance.is_some() {
                        invalid_statements.push(json!({"source_record_id":source.source_record_id,"statement_id":statement.statement_id,"code":"invalid_default"}));
                    } else {
                        let disposition = disposition.expect("checked").to_string();
                        default_outcomes.insert(disposition.clone());
                        matched_defaults.push(json!({"statement_id":statement.statement_id,"source_record_id":source.source_record_id,"disposition":disposition}));
                    }
                }
                "judgment_clause" => {
                    if statement.effect.is_some() || statement.guidance.as_deref().is_none_or(|value| value.trim().is_empty()) {
                        invalid_statements.push(json!({"source_record_id":source.source_record_id,"statement_id":statement.statement_id,"code":"invalid_judgment_clause"}));
                    } else {
                        matched_judgment_clauses.push(json!({"statement_id":statement.statement_id,"source_record_id":source.source_record_id}));
                    }
                }
                _ => invalid_statements.push(json!({"source_record_id":source.source_record_id,"statement_id":statement.statement_id,"code":"unknown_statement_kind"})),
            }
        }
    }
    let mut conflicts = Vec::new();
    let (disposition, default_statement_id) = if !invalid_statements.is_empty() {
        conflicts.push(json!({"code":"invalid_active_policy","items":invalid_statements}));
        ("block_and_request_authority".to_string(), Value::Null)
    } else if hard_outcomes.len() > 1 {
        conflicts.push(json!({"code":"hard_rule_conflict","outcomes":hard_outcomes}));
        ("block_and_request_authority".to_string(), Value::Null)
    } else if let Some(disposition) = hard_outcomes.into_iter().next() {
        (disposition, Value::Null)
    } else if default_outcomes.len() > 1 {
        conflicts.push(json!({"code":"default_conflict","outcomes":default_outcomes}));
        ("block_and_request_authority".to_string(), Value::Null)
    } else if let Some(disposition) = default_outcomes.into_iter().next() {
        let id = matched_defaults
            .first()
            .and_then(|value| value.get("statement_id"))
            .cloned()
            .unwrap_or(Value::Null);
        (disposition, id)
    } else {
        (
            DEFAULT_DISPOSITION.to_string(),
            Value::String("engine:unclassified-free-form".into()),
        )
    };
    let mut trace = json!({
        "format":TRACE_FORMAT,
        "compiled_policy_digest":compiled_policy_digest,
        "context_digest":context_digest,
        "sources":compiled_sources,
        "matched_hard_rules":matched_hard_rules,
        "overrides":[],
        "conflicts":conflicts,
        "judgment":if matched_judgment_clauses.is_empty(){Value::Null}else{json!({"clause_ids":matched_judgment_clauses,"status":"not_evaluated","reason":"v1 walking skeleton has no registry-bound model evaluator"})},
        "default_statement_id":default_statement_id,
        "final_disposition":disposition,
        "semantic_boundary":"free-form prose is unclassified; only registry-derived structure and the typed send operation are deterministic",
        "evaluation_digest":"pending"
    });
    let evaluation_digest = evaluation_digest_for_trace(&trace)?;
    trace.as_object_mut().expect("trace object").insert(
        "evaluation_digest".into(),
        Value::String(evaluation_digest.clone()),
    );
    Ok(PolicyEvaluation {
        disposition,
        action,
        trace,
        evaluation_digest,
        action_digest,
        context_digest,
        compiled_policy_digest,
    })
}

pub fn intervention_request(action_digest: &str, recipients: &[String]) -> Value {
    json!({
        "kind":"approve_action",
        "action_digest":action_digest,
        "summary":"Approve delivery of this exact Message draft",
        "intended_recipient_ids":recipients,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace_with_source(binding_id: &str, record_id: &str) -> Value {
        json!({
            "format":TRACE_FORMAT,
            "sources":[{
                "binding_id":binding_id,
                "record_id":record_id,
                "source_digest":"source-digest-1",
                "scope":"workspace",
                "issuer_principal_id":"native/issuer",
                "statement_ids":["statement-1"]
            }],
            "matched_hard_rules":[{
                "statement_id":"statement-1",
                "source_record_id":record_id,
                "disposition":"block_and_request_authority"
            }],
            "conflicts":[],
            "final_disposition":"block_and_request_authority",
            "evaluation_digest":"digest",
        })
    }

    fn trace_with_unreadable(binding_id: &str, record_id: &str) -> Value {
        json!({
            "format":TRACE_FORMAT,
            "sources":[],
            "conflicts":[{"code":"invalid_active_policy","items":[
                {"binding_id":binding_id,"source_record_id":record_id,"code":"policy_source_unreadable"}
            ]}],
            "final_disposition":"block_and_request_authority",
            "evaluation_digest":"digest",
        })
    }

    #[test]
    fn record_ids_are_collected_from_sources_and_conflicts() {
        let admitted = trace_with_source("binding-1", "record-1");
        assert_eq!(policy_source_record_ids(&admitted), vec!["record-1"]);
        let unreadable = trace_with_unreadable("binding-2", "record-2");
        assert_eq!(policy_source_record_ids(&unreadable), vec!["record-2"]);
    }

    #[test]
    fn hidden_unreadable_source_keeps_the_conflict_but_loses_every_identifier() {
        let trace = trace_with_unreadable("binding-1", "record-1");
        let redacted = redact_trace_with_hidden(&trace, &["record-1".to_string()]);
        let text = redacted.to_string();
        for hidden in ["binding-1", "record-1"] {
            assert!(!text.contains(hidden), "{text}");
        }
        assert_eq!(redacted["final_disposition"], "block_and_request_authority");
        assert_eq!(
            redacted["conflicts"][0]["items"][0]["code"],
            "policy_source_unreadable"
        );
        assert_eq!(
            redacted["conflicts"][0]["items"][0]["binding_id"],
            REDACTED_POLICY_SOURCE_ID
        );
    }

    #[test]
    fn hidden_admitted_source_loses_digest_issuer_and_statements() {
        let trace = trace_with_source("binding-1", "record-1");
        let redacted = redact_trace_with_hidden(&trace, &["record-1".to_string()]);
        let text = redacted.to_string();
        for hidden in [
            "binding-1",
            "record-1",
            "source-digest-1",
            "native/issuer",
            "statement-1",
        ] {
            assert!(!text.contains(hidden), "{hidden} survived: {text}");
        }
        // Shape is unchanged; only the source's descriptors are replaced.
        assert_eq!(redacted["sources"][0]["scope"], "workspace");
        assert_eq!(
            redacted["sources"][0]["record_id"],
            REDACTED_POLICY_SOURCE_ID
        );
        assert_eq!(
            redacted["matched_hard_rules"][0]["source_record_id"],
            REDACTED_POLICY_SOURCE_ID
        );
    }

    #[test]
    fn redaction_is_stable_and_readable_sources_are_untouched() {
        let readable = trace_with_source("binding-1", "record-1");
        assert_eq!(redact_trace_with_hidden(&readable, &[]), readable);
        let hidden = vec!["record-1".to_string()];
        assert_eq!(
            redact_trace_with_hidden(&readable, &hidden),
            redact_trace_with_hidden(&readable, &hidden)
        );
    }
}
