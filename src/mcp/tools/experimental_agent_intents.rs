//! Opt-in MCP development door for the provisional freshness agent seam.

use serde_json::{json, Value};

use crate::db::Db;
use crate::error::Result;
use crate::freshness::{execute_experimental_agent_intent, ExperimentalAgentIntent};

use super::super::{Caller, CustomInteractionPolicy, ToolExposure, ToolRegistry};
use super::{parse_args, principal};

const TOOL: &str = "experimental_freshness_agent_intent";

fn revision_ref_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "subject_kind": { "type": "string", "enum": ["unit", "artefact"] },
            "subject_id": { "type": "string", "minLength": 1, "maxLength": 200 },
            "revision_event_id": { "type": "string", "minLength": 1, "maxLength": 200 },
            "revision_seq": { "type": "integer", "minimum": 1 },
            "source_slot": { "type": "string", "enum": ["unit_content", "record_body", "blob"] },
            "sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
        },
        "required": ["subject_kind", "subject_id", "revision_event_id", "revision_seq", "source_slot", "sha256"],
        "additionalProperties": false
    })
}

fn selector_schema() -> Value {
    json!({
        "oneOf": [
            {
                "type": "object",
                "properties": {
                    "type": { "const": "text_quote" },
                    "exact": { "type": "string", "minLength": 1 },
                    "prefix": { "type": "string" },
                    "suffix": { "type": "string" },
                    "position_hint": { "type": "integer", "minimum": 0 }
                },
                "required": ["type", "exact"],
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": {
                    "type": { "const": "data_position" },
                    "start": { "type": "integer", "minimum": 0 },
                    "end": { "type": "integer", "minimum": 1 },
                    "selected_sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
                },
                "required": ["type", "start", "end"],
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": {
                    "type": { "const": "fragment" },
                    "conforms_to": { "type": "string", "minLength": 1 },
                    "value": { "type": "string", "minLength": 1 }
                },
                "required": ["type", "conforms_to", "value"],
                "additionalProperties": false
            }
        ]
    })
}

fn promote_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "source_revision": revision_ref_schema(),
            "selectors": { "type": "array", "minItems": 1, "items": selector_schema() },
            "first_content": {
                "type": "object",
                "properties": {
                    "content": { "type": "string", "minLength": 1 },
                    "content_media_type": { "type": "string", "minLength": 3 },
                    "encoding_version": { "type": "integer", "minimum": 1 }
                },
                "required": ["content", "content_media_type", "encoding_version"],
                "additionalProperties": false
            },
            "expression_role": { "type": "string", "enum": ["canonical", "paraphrase", "summary", "quotation"] },
            "label": { "type": "string" },
            "requested_unit_id": { "type": "string", "minLength": 1, "maxLength": 200 },
            "requested_occurrence_id": { "type": "string", "minLength": 1, "maxLength": 200 },
            "idempotency_key": { "type": "string", "minLength": 1, "maxLength": 200 }
        },
        "required": ["source_revision", "selectors", "first_content", "expression_role", "idempotency_key"],
        "additionalProperties": false
    })
}

fn context_request_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "intent": { "type": "string", "minLength": 1 },
            "task_scope": { "type": "string", "minLength": 1 },
            "risk_inputs": { "type": "array", "items": { "type": "string", "minLength": 1 }, "uniqueItems": true }
        },
        "required": ["intent", "task_scope"],
        "additionalProperties": false
    })
}

fn policy_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "continue_by_default": { "type": "boolean" },
            "disclosure_rule": { "type": "string", "enum": ["material_only", "explain_on_inspection"] },
            "hard_stop_categories": { "type": "array", "items": { "type": "string", "minLength": 1 }, "uniqueItems": true },
            "dependency_budget": { "type": "integer", "minimum": 1 },
            "version": { "type": "string", "minLength": 1 }
        },
        "required": ["continue_by_default", "disclosure_rule", "dependency_budget", "version"],
        "additionalProperties": false
    })
}

fn conclusion_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "key": { "type": "string", "minLength": 1 },
            "description": { "type": "string", "minLength": 1 }
        },
        "required": ["key", "description"],
        "additionalProperties": false
    })
}

fn source_reliance_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "source_revision": revision_ref_schema(),
            "dependency_id": { "type": "string", "minLength": 1, "maxLength": 200 },
            "semantic_role": { "type": "string", "minLength": 1 },
            "provenance_reason": { "type": "string", "minLength": 1 },
            "rationale": { "type": "string", "minLength": 1 },
            "reconsideration_trigger": { "type": "string", "minLength": 1 },
            "confidence": { "type": "number", "minimum": 0, "maximum": 1 }
        },
        "required": ["source_revision", "dependency_id", "semantic_role", "provenance_reason", "rationale", "reconsideration_trigger"],
        "additionalProperties": false
    })
}

fn durable_output_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "consumer_record_id": { "type": "string", "minLength": 1 },
            "expected_consumer_revision": revision_ref_schema(),
            "output_body": { "type": "string", "minLength": 1 },
            "request": context_request_schema(),
            "policy": policy_schema(),
            "source_record_ids": { "type": "array", "items": { "type": "string", "minLength": 1 }, "uniqueItems": true },
            "affected_conclusion": conclusion_schema(),
            "sources": { "type": "array", "items": source_reliance_schema() },
            "idempotency_key": { "type": "string", "minLength": 1, "maxLength": 200 }
        },
        "required": ["consumer_record_id", "expected_consumer_revision", "output_body", "request", "policy", "source_record_ids", "affected_conclusion", "sources", "idempotency_key"],
        "additionalProperties": false
    })
}

fn materiality_outcome_schema() -> Value {
    json!({
        "type": "string",
        "enum": ["immaterial", "remains_valid", "material", "materially_uncertain", "contradicted", "unable_to_assess"]
    })
}

fn assessment_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "assessment_id": { "type": "string", "minLength": 1, "maxLength": 200 },
            "dependency_id": { "type": "string", "minLength": 1, "maxLength": 200 },
            "compared_source_revision": revision_ref_schema(),
            "category": { "type": "string", "minLength": 1 },
            "outcome": materiality_outcome_schema(),
            "could_materially_change": { "type": "boolean" },
            "rationale": { "type": "string", "minLength": 1 },
            "uncertainty_id": { "type": "string", "minLength": 1, "maxLength": 200 },
            "uncertainty_evidence": { "type": "string", "minLength": 1 },
            "uncertainty_detail": { "type": "string", "minLength": 1 }
        },
        "required": ["assessment_id", "dependency_id", "compared_source_revision", "category", "outcome", "could_materially_change", "rationale"],
        "additionalProperties": false
    })
}

fn reconcile_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "reconciliation_id": { "type": "string", "minLength": 1, "maxLength": 200 },
            "dependency_id": { "type": "string", "minLength": 1, "maxLength": 200 },
            "assessed_source_revision": revision_ref_schema(),
            "task_scope": { "type": "string", "minLength": 1 },
            "outcome": materiality_outcome_schema(),
            "rationale": { "type": "string", "minLength": 1 },
            "idempotency_key": { "type": "string", "minLength": 1, "maxLength": 200 }
        },
        "required": ["reconciliation_id", "dependency_id", "assessed_source_revision", "task_scope", "outcome", "rationale", "idempotency_key"],
        "additionalProperties": false
    })
}

fn intent_schema() -> Value {
    json!({
        "type": "object",
        "oneOf": [
            {
                "type": "object",
                "properties": {
                    "intention": { "const": "promote_exact_expression" },
                    "input": promote_input_schema()
                },
                "required": ["intention", "input"],
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": {
                    "intention": { "const": "declare_sources" },
                    "output": durable_output_schema()
                },
                "required": ["intention", "output"],
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": {
                    "intention": { "const": "assess_exact_change" },
                    "output": durable_output_schema(),
                    "assessments": { "type": "array", "minItems": 1, "items": assessment_schema() }
                },
                "required": ["intention", "output", "assessments"],
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": {
                    "intention": { "const": "reconcile_affected_output" },
                    "receipt_id": { "type": "string", "minLength": 1, "maxLength": 200 },
                    "input": reconcile_input_schema()
                },
                "required": ["intention", "receipt_id", "input"],
                "additionalProperties": false
            }
        ]
    })
}

async fn execute(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let intention: ExperimentalAgentIntent = parse_args(TOOL, arguments)?;
    Ok(serde_json::to_value(
        execute_experimental_agent_intent(&db, principal(&caller), caller.actor(), intention)
            .await?,
    )?)
}

pub fn register_experimental_agent_intent_tool(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_custom(
        TOOL,
        // The semantic writes remain attributable through their real events and
        // run context. This experimental extension is deliberately excluded
        // from the stable shipped-tool read-log extractor.
        CustomInteractionPolicy::NoRecordInteractions,
        // Keep this large provisional grammar out of the near-full Focused
        // descriptor. Complete discovery and exact-name dispatch remain
        // available when the feature is enabled.
        ToolExposure::extension(false),
        "EXPERIMENTAL, feature-gated development probe. Execute exactly one of four freshness intentions through the real Unit/Receipt runtime: promote an exact expression, declare exact sources for one bounded conclusion, assess exact source change for the current task, or reconcile an affected output. Returns exact semantic evidence. This is not a stable public API; it performs no automatic idea extraction, prompt policy, calibration, or background repair.",
        intent_schema(),
        execute,
    )
}
