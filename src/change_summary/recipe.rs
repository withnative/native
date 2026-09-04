use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::Result;
use crate::recipe::{
    validate_recipe_definition, RecipeBudgetField, RecipeBudgetLimits, RecipeBudgetPolicy,
    RecipeContract, RecipeDefinition, RecipeExecutionProfile, RecipeInputClass, RecipeInstructions,
    RecipeModelCapability, RecipeRenderer, RecipeRepairPolicy, RECIPE_RUNTIME,
};

use super::render::{
    change_summary_renderer_sha256, CHANGE_SUMMARY_RENDERER_ID, CHANGE_SUMMARY_RENDERER_REVISION,
};
use super::schema::{
    change_summary_output_schema, change_summary_query_schema, change_summary_result_schema,
    CHANGE_SUMMARY_OUTPUT_CONTRACT_ID, CHANGE_SUMMARY_OUTPUT_CONTRACT_VERSION,
    CHANGE_SUMMARY_QUERY_CONTRACT_ID, CHANGE_SUMMARY_QUERY_CONTRACT_VERSION,
    CHANGE_SUMMARY_RESULT_CONTRACT_ID, CHANGE_SUMMARY_RESULT_CONTRACT_VERSION,
};

pub const CHANGE_SUMMARY_RECIPE_PROGRAM_ID: &str = "native:recipe:change-summary:v1";
pub const CHANGE_SUMMARY_INSTRUCTIONS_REVISION: &str = "native.change-summary.instructions.v1";
pub const CHANGE_SUMMARY_INSTRUCTIONS: &str = "Produce one materiality-aware change summary from exactly three authoritative source content events and only explicitly manifested context bodies. Return exactly one item citing all three source inputs by exact ordinal, role, kind, portable id, and sha256; cite every context record used by materiality or a link suggestion. Supply exactly three source groups, each bound by ordinal to one cited source and carrying that event's authoritative full run key. State the effective work interval in canonical UTC millisecond timestamps; it is work time, not derivation or transaction time. Pin the declared renderer id, revision, and specification sha256. Before returning, sort citations and source groups by ordinal, materiality references by record_id, and each WorkItem or Outcome suggestion array by record_id then relationship; never emit duplicates. Outcome suggestions may name only realised Outcome kind:impact records. Link suggestions are advisory: do not claim that links were created.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeSummaryRecipeProgramDescriptor {
    pub id: &'static str,
    pub record_type: &'static str,
    pub kind: &'static str,
    pub runtime: &'static str,
}

pub const CHANGE_SUMMARY_RECIPE_PROGRAM: ChangeSummaryRecipeProgramDescriptor =
    ChangeSummaryRecipeProgramDescriptor {
        id: CHANGE_SUMMARY_RECIPE_PROGRAM_ID,
        record_type: "Program",
        kind: "recipe",
        runtime: RECIPE_RUNTIME,
    };

fn sha256_bytes(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn contract(id: &str, version: u32, schema: Value) -> RecipeContract {
    let schema_sha256 = crate::derivation::digest_json(&schema);
    RecipeContract {
        id: id.into(),
        version,
        schema,
        schema_sha256,
    }
}

pub fn change_summary_recipe_definition() -> Result<RecipeDefinition> {
    let definition = RecipeDefinition {
        instructions: RecipeInstructions {
            revision: CHANGE_SUMMARY_INSTRUCTIONS_REVISION.into(),
            text: CHANGE_SUMMARY_INSTRUCTIONS.into(),
            sha256: sha256_bytes(CHANGE_SUMMARY_INSTRUCTIONS.as_bytes()),
        },
        query_contract: contract(
            CHANGE_SUMMARY_QUERY_CONTRACT_ID,
            CHANGE_SUMMARY_QUERY_CONTRACT_VERSION,
            change_summary_query_schema(),
        ),
        allowed_input_classes: vec![RecipeInputClass::ContentEvent, RecipeInputClass::RecordBody],
        result_contract: contract(
            CHANGE_SUMMARY_RESULT_CONTRACT_ID,
            CHANGE_SUMMARY_RESULT_CONTRACT_VERSION,
            change_summary_result_schema(),
        ),
        output_contract: contract(
            CHANGE_SUMMARY_OUTPUT_CONTRACT_ID,
            CHANGE_SUMMARY_OUTPUT_CONTRACT_VERSION,
            change_summary_output_schema(),
        ),
        renderer: RecipeRenderer {
            id: CHANGE_SUMMARY_RENDERER_ID.into(),
            revision: CHANGE_SUMMARY_RENDERER_REVISION.into(),
            sha256: change_summary_renderer_sha256(),
        },
        budgets: RecipeBudgetPolicy {
            supported_fields: vec![
                RecipeBudgetField::MaxInputBytes,
                RecipeBudgetField::MaxInputItems,
                RecipeBudgetField::MaxInputTokens,
                RecipeBudgetField::MaxOutputBytes,
                RecipeBudgetField::MaxOutputTokens,
            ],
            defaults: RecipeBudgetLimits {
                max_input_bytes: 262_144,
                max_input_items: 19,
                max_input_tokens: 32_768,
                max_output_bytes: 131_072,
                max_output_tokens: 4_096,
            },
            maxima: RecipeBudgetLimits {
                max_input_bytes: 1_048_576,
                max_input_items: 19,
                max_input_tokens: 131_072,
                max_output_bytes: 131_072,
                max_output_tokens: 16_384,
            },
        },
        contextual_inputs: Vec::new(),
        execution_profile: RecipeExecutionProfile {
            profile_id: "native.change-summary.structured-output.v1".into(),
            required_capabilities: vec![RecipeModelCapability::JsonSchemaOutput],
            temperature_milli: 0,
            max_output_tokens: 4_096,
        },
        repair_policy: RecipeRepairPolicy {
            max_repairs: 0,
            max_validation_errors: 32,
            repair_profile_id: None,
        },
    };
    validate_recipe_definition(&definition)?;
    Ok(definition)
}
