//! Product contract for materiality-aware change summaries.
//!
//! A change summary remains an ordinary note carried by the generic derivation
//! and confirmation substrates. This module defines the portable product
//! contracts and the first-party workflow that composes those primitives.

mod recipe;
mod render;
mod schema;
mod workflow;

pub use recipe::{
    change_summary_recipe_definition, ChangeSummaryRecipeProgramDescriptor,
    CHANGE_SUMMARY_INSTRUCTIONS, CHANGE_SUMMARY_INSTRUCTIONS_REVISION,
    CHANGE_SUMMARY_RECIPE_PROGRAM, CHANGE_SUMMARY_RECIPE_PROGRAM_ID,
};
pub use render::{
    change_summary_renderer_identity, change_summary_renderer_sha256, render_change_summary,
    render_change_summary_output, ChangeSummaryRenderedOutput, CHANGE_SUMMARY_MAX_RENDERED_BYTES,
    CHANGE_SUMMARY_MAX_RENDERED_CHARACTERS, CHANGE_SUMMARY_RENDERER_ID,
    CHANGE_SUMMARY_RENDERER_REVISION, CHANGE_SUMMARY_RENDERER_SHA256, CHANGE_SUMMARY_RENDERER_SPEC,
};
pub use schema::{
    canonicalize_and_validate_change_summary, canonicalize_change_summary_result,
    change_summary_output_schema, change_summary_query_schema, change_summary_result_schema,
    decode_and_validate_change_summary, validate_change_summary, validate_change_summary_manifest,
    validate_change_summary_query, validate_change_summary_result_schema,
    CanonicalChangeSummaryResult, ChangeSummary, ChangeSummaryCitation, ChangeSummaryContextRecord,
    ChangeSummaryEffectiveWorkInterval, ChangeSummaryInputManifest, ChangeSummaryItem,
    ChangeSummaryLinkSuggestion, ChangeSummaryLinkSuggestions, ChangeSummaryManifestInput,
    ChangeSummaryMateriality, ChangeSummaryMaterialityReference, ChangeSummaryQuery,
    ChangeSummaryRendererIdentity, ChangeSummaryResolver, ChangeSummaryScope,
    ChangeSummarySelection, ChangeSummarySourceEvent, ChangeSummarySourceGroup,
    CHANGE_SUMMARY_OUTPUT_CONTRACT_ID, CHANGE_SUMMARY_OUTPUT_CONTRACT_VERSION,
    CHANGE_SUMMARY_OUTPUT_SCHEMA_JSON, CHANGE_SUMMARY_QUERY_CONTRACT_ID,
    CHANGE_SUMMARY_QUERY_CONTRACT_VERSION, CHANGE_SUMMARY_QUERY_SCHEMA_JSON,
    CHANGE_SUMMARY_RESULT_CONTRACT_ID, CHANGE_SUMMARY_RESULT_CONTRACT_VERSION,
    CHANGE_SUMMARY_RESULT_SCHEMA, CHANGE_SUMMARY_RESULT_SCHEMA_JSON, CHANGE_SUMMARY_SCOPE_SCHEMA,
    CHANGE_SUMMARY_SELECTION_SCHEMA, MAX_CHANGE_SUMMARY_CONTEXT_RECORDS, MAX_CHANGE_SUMMARY_INPUTS,
    MAX_EFFECTIVE_WORK_INTERVAL_SECONDS,
};
pub use workflow::{
    confirm_change_summary, create_or_reuse_change_summary, inspect_change_summary,
    query_change_summaries, request_change_summary, revoke_change_summary, ChangeSummaryCandidate,
    ChangeSummaryConfirmation, ChangeSummaryCreateRequest, ChangeSummaryCurrentBasis,
    ChangeSummaryQueryPage, ChangeSummaryRecipePin, ChangeSummaryRequest,
    ChangeSummaryWorkflowInspection,
};

#[cfg(test)]
mod tests;
