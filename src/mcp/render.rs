//! Text renderings of tool payloads — the model-facing half of a tool result.
//!
//! This module exists on the TRANSPORT side of the seam, not in the handlers.
//! Decision 2231ad3 gives handlers one rule (structured data out, no
//! formatting) and makes rendering the transport's job; a renderer registered
//! next to its handler would quietly move formatting back across that line. So
//! renderers dispatch by tool NAME over the handler's already-structured
//! payload — which also means a renderer can never change what a caller of
//! `POST /tools/{name}` receives.
//!
//! ## Why a rendering is cheaper than the JSON it replaces
//!
//! Both `tools/call` sites used to emit `value.to_string()` into `content`
//! AND the same value into `structuredContent` — the same bytes twice, with
//! the model-facing copy in the least legible form JSON has (minified). A prose
//! rendering makes `content` readable. Audited standalone default-text
//! renderer families omit that duplicate. Explicit JSON, MCP Apps,
//! conservative mutation/mixed families, and defensive recovery retain it.
//!
//! ## The one rule renderers follow
//!
//! **A rendering may compress, but it may not lie.** Every truncation says it
//! truncated, every window says it was a window, and any count the payload
//! reports is reported here too — an agent that cannot see it was given a page
//! will conclude it was given the set. Where a payload carries an explicit
//! total next to a windowed list (`child_count`, `links_out_count`, `total`),
//! the rendering shows the total, not just what fit.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde_json::{json, Map, Value};

mod artifacts;
mod relationships;

/// Which representation a `tools/call` result carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// `content` holds the prose rendering. Audited standalone families omit
    /// duplicate `structuredContent`; conservative families retain it.
    Text,
    /// `content` holds the serialized JSON and `structuredContent` the object
    /// — MCP's documented pairing, byte-identical to what CE emitted before
    /// this module existed.
    Json,
    /// Internal-only MCP Apps framing. The model reads prose `content` while
    /// the view receives the same handler value in `structuredContent`.
    /// Callers cannot select this with the public `format` argument; registry
    /// UI metadata selects it automatically.
    App,
}

/// A prose rendering together with the compatibility data it still needs.
///
/// Audited text renderings can stand alone without a duplicate structured
/// payload. Mutation, mixed-action, and defensive paths are conservative.
/// Carrying the decision beside the text prevents protocol framing from having
/// to infer safety from prose or know individual tool-shape rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RenderOutcome {
    pub(crate) text: String,
    pub(crate) requires_structured_fallback: bool,
}

/// The tools with a renderer, in surface order. A tool absent from this list
/// falls back to [`Format::Json`] and is unaffected by any of this.
///
/// Kept as one list rather than inferred from [`render`] so that the default
/// resolution, the advertised schema and the dispatch cannot disagree — a
/// renderer that exists but is never reached is exactly the drift this file is
/// most likely to grow.
const RENDERED_TOOLS: [&str; 70] = [
    "bootstrap",
    "quickstart",
    "get_structure",
    "get_dashboard",
    "describe_schema",
    "read_guide",
    "create_record",
    "create_many",
    "get_record",
    "resolve_many",
    "update_record",
    "claim_unowned_record",
    "correct_record_type",
    "delete_record",
    "archive_record",
    "render_record",
    "get_history",
    "whats_changed",
    "manage_bindings",
    "manage_record_policy",
    "resolve_external",
    "observe_external",
    "get_run_activity",
    "get_event_context",
    "render_record_version_diff",
    "manage_links",
    "manage_relationships",
    "create_exploration",
    "instantiate_artifact",
    "manage_renderer_binding",
    "manage_mdx_modules",
    "manage_artifact_inputs",
    "manage_artifact_module_grants",
    "render_artifact",
    "verify_artifact",
    "invoke_artifact_interaction",
    "open_collection",
    "manage_facet_observations",
    "resolve_facets",
    "suggest_facet_values",
    "query_record",
    "resolve_rollup",
    "search",
    "query_sql",
    "scan",
    "manage_vocabularies",
    "manage_schema_config",
    "attach_text",
    "attach_from_url",
    "read_attachment",
    "manage_attachments",
    "start_work",
    "resolve_suggestions",
    "render_suggestion_review",
    "resolve_citation",
    "manage_citations",
    "create_attribution",
    "read_attributions",
    "manage_attributions",
    "manage_instructions",
    "manage_onboarding",
    "set_intent",
    "close_run",
    "manage_messages",
    "manage_interventions",
    "manage_change_summaries",
    "query_change_summaries",
    "preview_record_shape",
    "read_canvas",
    "manage_canvas",
];

/// The public response-control schema shared by every caller-selectable MCP
/// surface. Keeping the enum and default beside the runtime parser prevents a
/// descriptor from advertising a representation this transport cannot parse.
pub(crate) fn format_schema(tool: &str) -> Value {
    let default = match default_format(tool) {
        Format::Text => "text",
        Format::Json => "json",
        Format::App => unreachable!("App is transport-selected, never a public default"),
    };
    let values = if has_renderer(tool) {
        json!(["text", "json"])
    } else {
        json!(["json"])
    };
    json!({
        "type": "string",
        "enum": values,
        "default": default,
        "description": "Response representation. text is the compact model-facing rendering; json is exact serialized JSON plus structuredContent."
    })
}

/// Overlay `format` on the callable object grammar and its composed envelope
/// branches. Property schemas are deliberately not traversed: a nested object
/// is domain input, where representation controls remain unknown fields.
pub(crate) fn add_format_argument(schema: &mut Value, tool: &str) {
    add_format_schema(schema, &format_schema(tool));
}

/// Overlay an already-derived representation contract on a callable schema.
/// Executor surfaces use this when sibling operation discriminators make the
/// set of values conditional.
pub(crate) fn add_format_schema(schema: &mut Value, format_schema: &Value) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    object
        .entry("properties")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .expect("callable schema properties are an object")
        .insert("format".into(), format_schema.clone());
    add_format_branch_allowances(object);
}

fn add_format_branch_allowances(object: &mut serde_json::Map<String, Value>) {
    for keyword in ["oneOf", "anyOf", "allOf"] {
        if let Some(branches) = object.get_mut(keyword).and_then(Value::as_array_mut) {
            for branch in branches {
                let Some(branch) = branch.as_object_mut() else {
                    continue;
                };
                branch
                    .entry("properties")
                    .or_insert_with(|| json!({}))
                    .as_object_mut()
                    .expect("callable branch properties are an object")
                    .insert("format".into(), json!({}));
                add_format_branch_allowances(branch);
            }
        }
    }
}

/// Reject a caller-selected representation on a transport whose framing is
/// fixed outside the callable contract.
#[doc(hidden)]
pub fn reject_format(arguments: &Value, surface: &str) -> std::result::Result<(), String> {
    if arguments
        .as_object()
        .is_some_and(|arguments| arguments.contains_key("format"))
    {
        return Err(format!(
            "invalid arguments for {surface}: 'format' is not supported because this surface selects its response representation"
        ));
    }
    Ok(())
}

/// Does this tool have a text rendering — and therefore default to one?
pub fn has_renderer(tool: &str) -> bool {
    RENDERED_TOOLS.contains(&tool)
}

/// The format a tool answers in when the caller did not ask for one.
///
/// A tool that can render defaults to rendering. The alternative — render but
/// default to JSON — ships a mode nothing ever sees, since the agents this is
/// for do not read `tools/list` closely enough to opt in.
pub fn default_format(tool: &str) -> Format {
    if has_renderer(tool) {
        Format::Text
    } else {
        Format::Json
    }
}

/// Pull the `format` argument out of a call's arguments, leaving arguments the
/// handler will accept.
///
/// The stripping happens here, once, because every handler parses with
/// `deny_unknown_fields`: a `format` that reached one would be rejected as a
/// caller bug. Caller-selectable MCP transports call this before dispatch.
/// Fixed-format transports such as Apps, lenses, and workbench HTTP reject the
/// field instead of accepting a selector they cannot honour.
pub fn take_format(tool: &str, arguments: &mut Value) -> std::result::Result<Format, String> {
    let Some(object) = arguments.as_object_mut() else {
        // Not an object: leave it alone and let the handler's own parse
        // produce the error, which names the tool and the real problem.
        return Ok(default_format(tool));
    };
    let Some(raw) = object.remove("format") else {
        return Ok(default_format(tool));
    };
    match raw.as_str() {
        Some("text") if has_renderer(tool) => Ok(Format::Text),
        Some("text") => Err(format!(
            "invalid arguments for {tool}: 'format' cannot be \"text\" because this operation has no registered text renderer; use \"json\" or omit the field"
        )),
        Some("json") => Ok(Format::Json),
        _ => Err(format!(
            "invalid arguments for {tool}: 'format' must be \"text\" or \"json\""
        )),
    }
}

/// Render a tool's payload as text, or `None` if the tool has no rendering.
///
/// `None` is not a failure — it is the fallback path, and the caller answers
/// with JSON. Renderers are total over their payload's shape: a field that is
/// missing or the wrong type is skipped, never panicked on, because a payload
/// change should degrade the rendering rather than break the call.
pub fn render(tool: &str, value: &Value) -> Option<String> {
    render_outcome(tool, value).map(|outcome| outcome.text)
}

/// Render for an MCP transport, including whether compatibility data is
/// required for this particular payload.
///
/// The fallback decision is deliberately structural, not inferred from prose:
/// payload-authored text can contain any recovery-looking words. Read-only and
/// explicitly audited lossless mutation renderers are allowlisted; other
/// mutation and mixed-action families retain compatibility data.
pub(crate) fn render_outcome(tool: &str, value: &Value) -> Option<RenderOutcome> {
    let mut rendered = match tool {
        "bootstrap" => Some(render_bootstrap(value)),
        "standby_status" => Some(render_standby_status(value)),
        "quickstart" => Some(render_quickstart(value)),
        "read_guide" => Some(render_read_guide(value)),
        "get_structure" => Some(render_structure(value)),
        "get_dashboard" => Some(render_dashboard(value)),
        "describe_schema" => Some(render_describe_schema(value)),
        "preview_record_shape" => Some(render_record_shape_preview(value)),
        "read_canvas" => Some(render_read_canvas(value)),
        "manage_canvas" => Some(render_manage_canvas(value)),
        "create_record" => Some(render_enriched_write("Created", value)),
        "create_many" => Some(render_create_many(value)),
        "get_record" => Some(render_get_record(value, true)),
        "resolve_many" => Some(render_resolve_many(value)),
        "update_record" => Some(render_update_record(value)),
        "claim_unowned_record" => Some(render_ownership_claim(value)),
        "correct_record_type" => Some(render_record_type_correction(value)),
        "delete_record" => Some(render_delete_record(value)),
        "archive_record" => Some(render_archive_record(value)),
        "render_record" => Some(render_render_record(value)),
        "get_history" => Some(render_history(value)),
        "whats_changed" => Some(render_whats_changed(value)),
        "manage_bindings" => Some(render_identity_operation("Bindings", value)),
        "manage_record_policy" => Some(render_manage_record_policy(value)),
        "resolve_external" => Some(render_identity_operation("External identity", value)),
        "observe_external" => Some(render_identity_operation("External observation", value)),
        "get_run_activity" => Some(render_run_activity(value)),
        "get_event_context" => Some(render_event_context(value)),
        "create_exploration" => Some(render_exploration(value)),
        "render_record_version_diff" => Some(render_record_version_diff(value)),
        "manage_links" => Some(render_manage_links(value)),
        "manage_relationships" => Some(relationships::render_manage_relationships(value)),
        "instantiate_artifact" => Some(render_enriched_write("Instantiated", value)),
        "manage_renderer_binding" => Some(artifacts::render_manage_renderer_binding(value)),
        "manage_mdx_modules" => Some(render_management_result("MDX module management", value)),
        "manage_artifact_inputs" => {
            Some(render_management_result("Artifact input management", value))
        }
        "manage_artifact_module_grants" => Some(render_management_result(
            "Artifact capability grant management",
            value,
        )),
        "render_artifact" => Some(artifacts::render_artifact(value)),
        "verify_artifact" => Some(artifacts::render_verify_artifact(value)),
        "invoke_artifact_interaction" => Some(artifacts::render_artifact_interaction(value)),
        "open_collection" => Some(artifacts::render_open_collection(value)),
        "manage_facet_observations" => Some(render_manage_facet_observations(value)),
        "resolve_facets" => Some(render_resolve_facets(value)),
        "suggest_facet_values" => Some(render_suggest_facet_values(value)),
        "query_record" => Some(render_query_record(value)),
        "resolve_rollup" => Some(render_rollup(value)),
        "search" => Some(render_search(value)),
        "query_sql" => Some(render_query_sql(value)),
        "scan" => Some(render_scan(value)),
        "manage_vocabularies" => Some(render_manage_vocabularies(value)),
        "manage_schema_config" => Some(render_manage_schema_config(value)),
        "attach_text" | "attach_from_url" => Some(render_attachment_created(value)),
        "read_attachment" => Some(render_read_attachment(value)),
        "manage_attachments" => Some(render_manage_attachments(value)),
        "resolve_suggestions" => Some(render_resolve_suggestions(value)),
        "render_suggestion_review" => Some(render_suggestion_review(value)),
        "start_work" => Some(render_start_work(value)),
        "resolve_citation" => Some(render_resolve_citation(value)),
        "manage_citations" => Some(render_manage_citations(value)),
        "create_attribution" => Some(render_create_attribution(value)),
        "read_attributions" => Some(render_read_attributions(value)),
        "manage_attributions" => Some(render_manage_attributions(value)),
        "manage_instructions" => Some(render_manage_instructions(value)),
        "manage_onboarding" => Some(render_manage_onboarding(value)),
        "set_intent" => Some(render_set_intent(value)),
        "close_run" => Some(render_close_run(value)),
        "manage_messages" => Some(render_manage_messages(value)),
        "manage_interventions" => Some(render_manage_interventions(value)),
        "manage_change_summaries" => Some(render_manage_change_summaries(value)),
        "query_change_summaries" => Some(render_query_change_summaries(value)),
        _ => None,
    }?;
    if tool != "bootstrap" {
        if let Some(context) = value.get("standby_context") {
            rendered = format!("{}\n\n{rendered}", render_standby_context(context));
        }
    }
    if let Some(context) = value.get("run_context") {
        rendered.push_str(&render_run_context(context));
    }
    let requires_structured_fallback = renderer_family_requires_structured_fallback(tool);
    Some(RenderOutcome {
        text: rendered,
        requires_structured_fallback,
    })
}

fn render_standby_context(value: &Value) -> String {
    let mode = claimed_string(value.get("mode"), "mode");
    let freshness = claimed_string(value.pointer("/freshness/state"), "freshness");
    let mut out = format!(
        "Standby context: `{mode}` · read-only local replica · hosted Native is canonical · freshness `{freshness}`"
    );
    if let (Some(age), Some(rpo)) = (
        value
            .pointer("/freshness/age_seconds")
            .and_then(Value::as_u64),
        value
            .pointer("/freshness/target_rpo_seconds")
            .and_then(Value::as_u64),
    ) {
        let _ = write!(out, " ({age}s old; {rpo}s RPO)");
    }
    if let Some(action) = string(value, "next_safe_action") {
        let _ = write!(out, ". Next safe action: {action}.");
    }
    out
}

fn render_standby_status(value: &Value) -> String {
    let mut out = String::from("# Local standby status\n\n");
    if let Some(summary) = string(value, "summary") {
        let _ = writeln!(out, "{summary}");
    }
    let mode = claimed_string(value.get("mode"), "mode");
    let freshness = claimed_string(value.pointer("/freshness/state"), "freshness");
    let _ = writeln!(
        out,
        "\nMode: `{mode}` · read-only · writes unsupported · canonical authority: hosted"
    );
    let _ = write!(out, "Freshness: `{freshness}`");
    if let (Some(age), Some(rpo)) = (
        value
            .pointer("/freshness/age_seconds")
            .and_then(Value::as_u64),
        value
            .pointer("/freshness/target_rpo_seconds")
            .and_then(Value::as_u64),
    ) {
        let _ = write!(out, " · snapshot age {age}s · target RPO {rpo}s");
    }
    out.push('\n');
    if let Some(id) = value
        .pointer("/serving_generation/generation_id")
        .and_then(Value::as_str)
    {
        let _ = writeln!(out, "Serving generation: `{id}`");
    } else {
        out.push_str("Serving generation: none\n");
    }
    if let Some(id) = value
        .pointer("/accepted_generation/generation_id")
        .and_then(Value::as_str)
    {
        let _ = writeln!(out, "Accepted generation: `{id}`");
    }
    let reasons = array(value, "degraded_reasons");
    if !reasons.is_empty() {
        out.push_str("Degraded reasons:");
        for reason in reasons.iter().filter_map(Value::as_str) {
            let _ = write!(out, " `{reason}`");
        }
        out.push('\n');
    }
    if let Some(action) = string(value, "next_safe_action") {
        let _ = writeln!(out, "Next safe action: {action}.");
    }
    out
}

/// Conservative typed boundary: retention is the default, and only audited
/// read-only or lossless-over-future-fields renderer families can omit the
/// compatibility payload.
///
/// This intentionally retains the duplicate for complete results in these
/// mutation/mixed families too. It is a safe stepping stone: individual families
/// can later return a finer-grained `RenderOutcome` without weakening the
/// transport invariant or inspecting user-controlled prose.
fn renderer_family_requires_structured_fallback(tool: &str) -> bool {
    !matches!(
        tool,
        "bootstrap"
            | "standby_status"
            | "quickstart"
            | "get_structure"
            | "get_dashboard"
            | "describe_schema"
            | "read_guide"
            | "get_record"
            | "resolve_many"
            | "render_record"
            | "get_history"
            | "whats_changed"
            | "get_run_activity"
            | "get_event_context"
            | "render_record_version_diff"
            | "render_artifact"
            | "verify_artifact"
            | "open_collection"
            | "resolve_facets"
            | "suggest_facet_values"
            | "query_record"
            | "resolve_rollup"
            | "search"
            | "query_sql"
            | "scan"
            | "read_attachment"
            | "render_suggestion_review"
            | "resolve_citation"
            | "read_attributions"
            | "query_change_summaries"
            | "preview_record_shape"
            | "read_canvas"
            | "create_record"
            | "update_record"
            | "instantiate_artifact"
            | "manage_bindings"
            | "observe_external"
            | "create_exploration"
            | "manage_mdx_modules"
            | "manage_artifact_inputs"
            | "manage_artifact_module_grants"
            | "attach_text"
            | "attach_from_url"
            | "manage_messages"
            | "manage_instructions"
            | "manage_onboarding"
            | "manage_vocabularies"
            | "manage_schema_config"
    )
}

const CHANGE_SUMMARY_DETAIL_BUDGET: usize = 24_000;
const READ_JSON_RECOVERY: &str = "Re-call this read with the same arguments and format:\"json\" for a fresh exact JSON projection.";
const READ_JSON_SHORTENED_RECOVERY: &str =
    " (shortened; re-call this read with the same arguments and format:\"json\" for a fresh exact JSON projection)";

fn render_change_summary_unknowns(
    out: &mut String,
    label: &str,
    value: &Value,
    known: impl Fn(&str) -> bool,
) {
    let unknown = unknown_object_keys(value, known);
    if !unknown.is_empty() {
        let encoded = inline_json(&json!(unknown));
        let (preview, shortened) = one_line_preview(&encoded, 1_000);
        let _ = writeln!(
            out,
            "Additional {label} fields omitted from text: {preview}{}; exact current values remain in structuredContent.",
            if shortened {
                " (field-name list shortened)"
            } else {
                ""
            }
        );
    }
}

fn render_change_summary_unknowns_bounded(
    out: &mut String,
    label: &str,
    value: &Value,
    known: impl Fn(&str) -> bool,
    remaining: &mut usize,
) {
    let unknown = unknown_object_keys(value, known);
    if unknown.is_empty() {
        return;
    }
    if !render_bounded_query_json_line(
        out,
        &format!(
            "Additional {label} fields omitted from text (re-call this read with the same arguments and format:\"json\" for exact values): "
        ),
        &json!(unknown),
        remaining,
        READ_JSON_SHORTENED_RECOVERY,
    ) {
        let _ = writeln!(
            out,
            "Additional {label} field names omitted because the shared detail budget was exhausted; {READ_JSON_RECOVERY}"
        );
    }
}

fn render_change_summary_request(out: &mut String, request: &Value, remaining: &mut usize) {
    let Some(_) = request.as_object() else {
        out.push_str(
            "Request state is malformed and was not interpreted; inspect structuredContent.\n",
        );
        return;
    };
    if let Some(details) =
        exact_known_object_remainder(request, &["spec", "failure_metadata"], |key| {
            matches!(
                key,
                "id" | "request_key_sha256"
                    | "requested_by"
                    | "requested_run_key"
                    | "state"
                    | "lease_owner"
                    | "lease_run_key"
                    | "lease_generation"
                    | "lease_expires_at"
                    | "attempt_count"
                    | "retryable"
                    | "next_attempt_at"
                    | "failure_code"
                    | "result_revision_id"
                    | "created_at"
                    | "updated_at"
            )
        })
    {
        if !render_bounded_query_json_line(
            out,
            "Request: ",
            &details,
            remaining,
            " (shortened; exact current request remains in structuredContent)",
        ) {
            out.push_str("Request detail omitted because the shared detail budget was exhausted; exact current request remains in structuredContent.\n");
        }
    }
    if request.get("spec").is_some() || request.get("failure_metadata").is_some() {
        out.push_str("Request spec/failure detail is retained in structuredContent.\n");
    }
    render_change_summary_unknowns(out, "request", request, |key| {
        matches!(
            key,
            "id" | "request_key_sha256"
                | "spec"
                | "requested_by"
                | "requested_run_key"
                | "state"
                | "lease_owner"
                | "lease_run_key"
                | "lease_generation"
                | "lease_expires_at"
                | "attempt_count"
                | "retryable"
                | "next_attempt_at"
                | "failure_code"
                | "failure_metadata"
                | "result_revision_id"
                | "created_at"
                | "updated_at"
        )
    });
}

fn render_manage_change_summaries(value: &Value) -> String {
    let Some(action) = value.get("action").and_then(Value::as_str) else {
        return "Change-summary outcome is missing its action discriminator; inspect structuredContent."
            .into();
    };
    if !matches!(
        action,
        "create_or_reuse" | "derive" | "inspect" | "confirm" | "revoke"
    ) {
        return format!(
            "Unsupported change-summary action {}; inspect structuredContent.",
            inline_json(&json!(action))
        );
    }

    let heading = match action {
        "create_or_reuse" => "Change-summary workflow created or reused.",
        "derive" => "Change-summary derivation requested.",
        "inspect" => "Change-summary workflow inspected.",
        "confirm" => "Change-summary revision confirmed.",
        "revoke" => "Change-summary confirmation revoked.",
        _ => unreachable!(),
    };
    let mut out = format!("{heading}\n");
    let mut remaining = CHANGE_SUMMARY_DETAIL_BUDGET;
    for (label, key) in [
        ("Schema", "schema"),
        ("Workflow", "workflow_key"),
        ("Carrier", "carrier_id"),
        ("Series", "series_id"),
        ("Binding", "binding_id"),
        ("Assignment", "assignment_id"),
        ("Selected revision", "selected_revision_id"),
        ("Selected publication", "selected_publication_id"),
        ("Confirmed revision", "confirmed_revision_id"),
        ("Revision", "revision_id"),
        ("Confirmation", "confirmation_id"),
        ("Event", "event_id"),
    ] {
        if let Some(found) = value.get(key) {
            if !render_bounded_query_json_line(
                &mut out,
                &format!("{label}: "),
                found,
                &mut remaining,
                " (shortened; exact current value remains in structuredContent)",
            ) {
                let _ = writeln!(
                    out,
                    "{label} omitted because the shared detail budget was exhausted."
                );
            }
        }
    }
    if let Some(seq) = value.get("event_seq").and_then(Value::as_i64) {
        let _ = writeln!(out, "Event seq: {seq}");
    }

    if action == "derive" {
        match (
            boolean(value, "executed"),
            value.pointer("/request/state").and_then(Value::as_str),
        ) {
            (Some(true), _) => out.push_str("Derivation executed and published a candidate.\n"),
            (Some(false), Some("succeeded")) => {
                out.push_str("Existing succeeded derivation result reused.\n")
            }
            (Some(false), Some("pending" | "running")) => {
                out.push_str("Derivation request joined; no completed result is claimed.\n")
            }
            (Some(false), Some("failed")) => {
                out.push_str("Derivation request is failed; no completed result is claimed.\n")
            }
            _ => out.push_str(
                "Derivation execution state is unavailable; no completed result is claimed.\n",
            ),
        }
        if let Some(created) = boolean(value, "created_request") {
            let _ = writeln!(out, "Request created by this call: {created}");
        }
    }
    if let Some(request) = value.get("request").filter(|value| !value.is_null()) {
        render_change_summary_request(&mut out, request, &mut remaining);
    }
    if let Some(body) = value.get("confirmed_body").filter(|value| !value.is_null()) {
        if !render_bounded_query_json_line(
            &mut out,
            "Confirmed body: ",
            body,
            &mut remaining,
            " (shortened; exact current body remains in structuredContent)",
        ) {
            out.push_str("Confirmed body omitted because the shared detail budget was exhausted; exact current body remains in structuredContent.\n");
        }
    }
    render_change_summary_unknowns(&mut out, "manage result", value, |key| {
        matches!(
            key,
            "action"
                | "schema"
                | "workflow_key"
                | "carrier_id"
                | "series_id"
                | "binding_id"
                | "assignment_id"
                | "selected_revision_id"
                | "selected_publication_id"
                | "confirmed_revision_id"
                | "confirmation_id"
                | "confirmed_body"
                | "request"
                | "revision_id"
                | "created_request"
                | "executed"
                | "event_id"
                | "event_seq"
                | "run_context"
        )
    });
    out.trim_end().into()
}

fn change_summary_evidence_projection(input: &Value) -> Option<Value> {
    let object = input.as_object()?;
    let redacted = object.get("redacted").and_then(Value::as_bool);
    let allowed = |key: &str| {
        matches!(key, "ordinal" | "input_role" | "input_kind" | "redacted")
            || (redacted == Some(false) && matches!(key, "portable_id" | "sha256" | "run_key"))
    };
    let mut projection = Value::Object(
        object
            .iter()
            .filter(|(key, _)| allowed(key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    );
    if redacted.is_none() {
        projection["redaction_status"] =
            Value::String("indeterminate; protected fields omitted".into());
    }
    Some(projection)
}

fn render_change_summary_evidence(out: &mut String, item: &Value, remaining: &mut usize) {
    let Some(inputs) = item.get("source_runs").and_then(Value::as_array) else {
        let _ = writeln!(
            out,
            "Evidence page is malformed or unavailable; {READ_JSON_RECOVERY}"
        );
        return;
    };
    let source_count = inputs
        .iter()
        .filter(|input| string(input, "input_role").as_deref() == Some("source"))
        .count();
    let context_count = inputs
        .iter()
        .filter(|input| string(input, "input_role").as_deref() == Some("context"))
        .count();
    let _ = writeln!(
        out,
        "Evidence page returned {} item(s): {source_count} source, {context_count} context.",
        inputs.len()
    );
    let mut budget_skipped = 0;
    for (index, input) in inputs.iter().enumerate() {
        let Some(projection) = change_summary_evidence_projection(input) else {
            let _ = writeln!(
                out,
                "- Evidence item {} is malformed; {READ_JSON_RECOVERY}",
                index + 1,
            );
            continue;
        };
        if !render_bounded_query_json_line(
            out,
            "- Evidence: ",
            &projection,
            remaining,
            READ_JSON_SHORTENED_RECOVERY,
        ) {
            budget_skipped += 1;
        }
        let unknown = unknown_object_keys(input, |key| {
            matches!(
                key,
                "ordinal"
                    | "input_role"
                    | "input_kind"
                    | "portable_id"
                    | "sha256"
                    | "run_key"
                    | "redacted"
            )
        });
        if !unknown.is_empty()
            && !render_bounded_query_json_line(
                out,
                "  Additional evidence fields omitted (re-call this read with format:\"json\" for exact values): ",
                &json!(unknown),
                remaining,
                " (field-name list shortened)",
            )
        {
            let _ = writeln!(out, "  Additional evidence field names omitted because the shared detail budget was exhausted; {READ_JSON_RECOVERY}");
        }
    }
    if budget_skipped > 0 {
        let _ = writeln!(out, "Evidence detail budget exhausted: {budget_skipped} returned item(s) omitted; {READ_JSON_RECOVERY}");
    }
}

fn render_change_summary_item(out: &mut String, item: &Value, remaining: &mut usize) {
    let Some(_) = item.as_object() else {
        let _ = writeln!(
            out,
            "Change-summary item is malformed; {READ_JSON_RECOVERY}"
        );
        return;
    };
    for (label, key) in [
        ("Assignment", "assignment_id"),
        ("Target", "target_record_id"),
        ("Role", "role"),
        ("Confirmation", "confirmation_id"),
        ("Series", "series_id"),
        ("Revision", "revision_id"),
        ("Publication", "publication_id"),
        ("Confirmed event", "confirmed_event_id"),
        ("Confirmed by", "confirmed_by"),
    ] {
        if let Some(found) = item.get(key).filter(|value| !value.is_null()) {
            if !render_bounded_query_json_line(
                out,
                &format!("{label}: "),
                found,
                remaining,
                READ_JSON_SHORTENED_RECOVERY,
            ) {
                let _ = writeln!(
                    out,
                    "{label} omitted because the shared detail budget was exhausted."
                );
            }
        }
    }
    if let Some(draft) = boolean(item, "draft_available") {
        let _ = writeln!(out, "Newer draft available: {draft}");
    }
    match (
        item.get("next_source_cursor"),
        item.get("assignment_id").and_then(Value::as_str),
    ) {
        (Some(Value::String(cursor)), Some(assignment)) => {
            let request = json!({"action":"drill","assignment_id":assignment,"cursor":cursor});
            let _ = writeln!(out, "Evidence continuation: {}", inline_json(&request));
        }
        (Some(Value::Null), _) => out.push_str("Evidence page exhausted.\n"),
        (Some(Value::String(_)), None) => out.push_str(
            "Evidence continuation is present but assignment_id is malformed or unavailable; re-call this read with the same arguments and format:\"json\" for a fresh exact JSON projection.\n",
        ),
        _ => out.push_str(
            "Evidence continuation state is malformed or unavailable; exhaustion is not claimed.\n",
        ),
    }
    render_change_summary_evidence(out, item, remaining);
    if let Some(body) = item.get("confirmed_body").filter(|value| !value.is_null()) {
        if !render_bounded_query_json_line(
            out,
            "Confirmed body preview: ",
            body,
            remaining,
            READ_JSON_SHORTENED_RECOVERY,
        ) {
            let _ = writeln!(out, "Confirmed body omitted because the shared detail budget was exhausted; {READ_JSON_RECOVERY}");
        }
    }
    render_change_summary_unknowns_bounded(
        out,
        "change-summary item",
        item,
        |key| {
            matches!(
                key,
                "action"
                    | "assignment_id"
                    | "target_record_id"
                    | "role"
                    | "confirmation_id"
                    | "series_id"
                    | "revision_id"
                    | "publication_id"
                    | "confirmed_event_id"
                    | "confirmed_by"
                    | "confirmed_body"
                    | "draft_available"
                    | "source_runs"
                    | "next_source_cursor"
                    | "run_context"
            )
        },
        remaining,
    );
}

fn render_compact_change_summary_handle(out: &mut String, item: &Value) -> bool {
    let Some(assignment) = item.get("assignment_id").and_then(Value::as_str) else {
        let _ = writeln!(
            out,
            "- Compact item handle is malformed; {READ_JSON_RECOVERY}"
        );
        return false;
    };
    if assignment.chars().count() > 512 {
        let _ = writeln!(
            out,
            "- Compact item assignment is too long to render safely; {READ_JSON_RECOVERY}"
        );
        return false;
    }
    let _ = write!(out, "- Assignment: {}", inline_json(&json!(assignment)));
    match item.get("next_source_cursor") {
        Some(Value::String(cursor)) if cursor.chars().count() <= 512 => {
            let request = json!({"action":"drill","assignment_id":assignment,"cursor":cursor});
            let _ = write!(out, " · evidence continuation: {}", inline_json(&request));
        }
        Some(Value::Null) => {}
        _ => out.push_str(" · continuation state unavailable"),
    }
    out.push('\n');
    true
}

fn render_query_change_summaries(value: &Value) -> String {
    let Some(action) = value.get("action").and_then(Value::as_str) else {
        return format!(
            "Change-summary query result is missing its action discriminator; {READ_JSON_RECOVERY}"
        );
    };
    let mut out = String::new();
    let mut remaining = CHANGE_SUMMARY_DETAIL_BUDGET;
    match action {
        "list" => {
            let Some(items) = value.get("items").and_then(Value::as_array) else {
                return format!("Change-summary list page is malformed; {READ_JSON_RECOVERY}");
            };
            let _ = writeln!(
                out,
                "Confirmed change-summary page: {} returned item(s).",
                items.len()
            );
            let mut compact_handles = 0;
            let mut compact_unavailable = 0;
            for (index, item) in items.iter().enumerate() {
                let _ = writeln!(out, "\nItem {}:", index + 1);
                if remaining == 0 {
                    if render_compact_change_summary_handle(&mut out, item) {
                        compact_handles += 1;
                    } else {
                        compact_unavailable += 1;
                    }
                } else {
                    render_change_summary_item(&mut out, item, &mut remaining);
                }
            }
            if compact_handles > 0 {
                let _ = writeln!(
                    out,
                    "Shared detail budget exhausted: {compact_handles} item(s) rendered as compact assignment handles; {READ_JSON_RECOVERY}"
                );
            }
            if compact_unavailable > 0 {
                let _ = writeln!(
                    out,
                    "Shared detail budget exhausted: {compact_unavailable} compact item(s) unavailable or malformed; {READ_JSON_RECOVERY}"
                );
            }
            match value.get("next_cursor") {
                Some(Value::String(cursor)) => {
                    let request = json!({"action":"list","cursor":cursor});
                    let _ = writeln!(out, "List continuation: {}", inline_json(&request));
                    out.push_str("A continuation scan is available; another page may contain more matching summaries.\n");
                }
                Some(Value::Null) => out.push_str("List scan exhausted.\n"),
                _ => out.push_str(
                    "List continuation state is malformed or unavailable; exhaustion is not claimed.\n",
                ),
            }
            render_change_summary_unknowns_bounded(
                &mut out,
                "list result",
                value,
                |key| matches!(key, "action" | "items" | "next_cursor" | "run_context"),
                &mut remaining,
            );
        }
        "get" => {
            out.push_str("Confirmed change summary.\n");
            render_change_summary_item(&mut out, value, &mut remaining);
        }
        "drill" => {
            out.push_str("Change-summary evidence page.\n");
            for (label, key) in [
                ("Assignment", "assignment_id"),
                ("Target", "target_record_id"),
                ("Revision", "revision_id"),
            ] {
                if let Some(found) = value.get(key).filter(|value| !value.is_null()) {
                    let _ = render_bounded_query_json_line(
                        &mut out,
                        &format!("{label}: "),
                        found,
                        &mut remaining,
                        READ_JSON_SHORTENED_RECOVERY,
                    );
                }
            }
            match (
                value.get("next_cursor"),
                value.get("assignment_id").and_then(Value::as_str),
            ) {
                (Some(Value::String(cursor)), Some(assignment)) => {
                    let request = json!({
                        "action":"drill",
                        "assignment_id":assignment,
                        "cursor":cursor
                    });
                    let _ = writeln!(out, "Evidence continuation: {}", inline_json(&request));
                }
                (Some(Value::Null), _) => out.push_str("Evidence page exhausted.\n"),
                (Some(Value::String(_)), None) => out.push_str(
                    "Evidence continuation is present but assignment_id is malformed or unavailable; re-call this read with the same arguments and format:\"json\" for a fresh exact JSON projection.\n",
                ),
                _ => out.push_str(
                    "Evidence continuation state is malformed or unavailable; exhaustion is not claimed.\n",
                ),
            }
            render_change_summary_evidence(&mut out, value, &mut remaining);
            render_change_summary_unknowns_bounded(
                &mut out,
                "drill result",
                value,
                |key| {
                    matches!(
                        key,
                        "action"
                            | "assignment_id"
                            | "target_record_id"
                            | "revision_id"
                            | "source_runs"
                            | "next_cursor"
                            | "run_context"
                    )
                },
                &mut remaining,
            );
        }
        _ => {
            return format!(
                "Unsupported change-summary query action {}; {READ_JSON_RECOVERY}",
                inline_json(&json!(action)),
            );
        }
    }
    out.trim_end().into()
}

fn render_manage_messages(value: &Value) -> String {
    // This tool is a union of writes, reads, delivery-policy outcomes and
    // awareness mutations. Most variants deliberately have no top-level
    // `status`, so absence cannot truthfully be interpreted as completion.
    let mut out = if let Some(status) = value.pointer("/delivery/status").and_then(Value::as_str) {
        format!("Message delivery: {}.\n", one_line(status, 80))
    } else if let Some(status) = string(value, "status") {
        format!("Message operation: {}.\n", one_line(&status, 80))
    } else if value.get("schema").and_then(Value::as_str)
        == Some(crate::awareness::MESSAGE_INBOX_SCHEMA)
        && ["view", "items", "snapshot", "next_after", "newer_available"]
            .iter()
            .all(|key| value.get(key).is_some())
    {
        let mut heading = "Message inbox page.".to_string();
        if value.get("next_after").is_some_and(|next| !next.is_null()) {
            heading.push_str(
                " More items remain in the pinned snapshot; continue with the returned snapshot, passing next_after as after.",
            );
        }
        if boolean(value, "newer_available") == Some(true) {
            heading.push_str(" Newer data also exists outside the pinned snapshot.");
        }
        heading.push('\n');
        heading
    } else if value.get("conversations").is_some() {
        "Message conversation list.\n".into()
    } else if value.get("messages").is_some() {
        "Message list result.\n".into()
    } else if value.get("destinations").is_some() {
        "Message destinations result.\n".into()
    } else if value.get("candidates").is_some() {
        "Notification candidate window; do not infer it is complete from this result alone.\n"
            .into()
    } else {
        "Message result.\n".into()
    };
    // Preserve the complete union member, including fields added by future
    // actions. JSON-encode even strings: Message bodies are untrusted,
    // multiline content and must not be able to impersonate labelled fields.
    if let Some(object) = value.as_object() {
        for (key, field) in object {
            if key != "run_context" {
                let _ = writeln!(out, "{key}: {}", inline_json(field));
            }
        }
    } else {
        let _ = writeln!(out, "{}", inline_json(value));
    }
    out
}

fn render_manage_interventions(value: &Value) -> String {
    let Some(action) = value.get("action").and_then(Value::as_str) else {
        return "Intervention response has no valid server-authored action; no outcome was inferred. Exact response remains in structuredContent.\n".into();
    };
    match action {
        "get" => render_intervention_view(value, true),
        "query" => render_intervention_query(value),
        "cancel" | "resume_delivery" => render_intervention_write(value, action),
        _ => format!(
            "Intervention action {} is unsupported; no outcome was inferred. Exact response remains in structuredContent.\n",
            inline_json(&json!(action))
        ),
    }
}

const INTERVENTION_TEXT_BUDGET: usize = 20_000;
const INTERVENTION_ITEM_LIMIT: usize = 50;
const INTERVENTION_RECOVERY: &str = "Exact response remains in structuredContent.";

fn intervention_nonblank(value: &Value) -> bool {
    value.as_str().is_some_and(|text| !text.trim().is_empty())
}

fn intervention_positive(value: &Value) -> bool {
    value.as_u64().is_some_and(|number| number > 0)
}

fn intervention_string_or_null(value: &Value) -> bool {
    value.is_null() || value.is_string()
}

fn intervention_string_array(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().all(intervention_nonblank))
}

fn intervention_action_snapshot_valid(value: &Value) -> bool {
    let Some(action) = value.get("action").and_then(Value::as_object) else {
        return false;
    };
    value
        .get("requested_outcome")
        .is_some_and(intervention_nonblank)
        && value
            .get("action_digest")
            .is_some_and(intervention_nonblank)
        && [
            "class",
            "operation",
            "destination_kind",
            "destination_workspace_id",
            "sensitivity",
        ]
        .into_iter()
        .all(|key| action.get(key).is_some_and(intervention_nonblank))
        && action.get("reversible").is_some_and(Value::is_boolean)
        && action
            .get("correspondent_principal_ids")
            .is_some_and(intervention_string_array)
        && action
            .get("disclosure_preview")
            .is_some_and(intervention_string_or_null)
}

fn intervention_state_valid(value: &Value) -> bool {
    let attention = value.get("attention");
    let obligation = value.get("obligation");
    let execution = value.get("execution");
    let timing = value.get("timing");
    attention.is_some_and(|attention| {
        attention.get("state").is_some_and(intervention_nonblank)
            && attention
                .get("source_format")
                .is_some_and(intervention_string_or_null)
    }) && obligation.is_some_and(|obligation| {
        ["format", "message_id", "recipient_id", "state"]
            .into_iter()
            .all(|key| obligation.get(key).is_some_and(intervention_nonblank))
            && obligation
                .get("expectation")
                .is_some_and(intervention_string_or_null)
            && obligation.get("evidence").is_none_or(|evidence| {
                evidence.is_object()
                    && ["kind", "record_id"]
                        .into_iter()
                        .all(|key| evidence.get(key).is_some_and(intervention_nonblank))
            })
    }) && execution.is_some_and(|execution| {
        matches!(
            execution.get("state").and_then(Value::as_str),
            Some("proceeded" | "blocked" | "resumed" | "cancelled")
        ) && execution
            .get("basis_event_seq")
            .is_some_and(intervention_positive)
    }) && timing.is_some_and(|timing| {
        timing.get("state").is_some_and(intervention_nonblank)
            && timing
                .get("respond_by")
                .is_some_and(intervention_string_or_null)
    })
}

fn intervention_affordance_valid(value: &Value) -> bool {
    value.get("kind").is_some_and(intervention_nonblank)
        && value.get("enabled").is_some_and(Value::is_boolean)
        && value
            .get("reason_code")
            .is_some_and(intervention_string_or_null)
}

fn intervention_viewer_valid(value: &Value) -> bool {
    value
        .get("intent_format")
        .is_some_and(intervention_nonblank)
        && [
            "supported_focus",
            "supported_evidence",
            "supported_controls",
        ]
        .into_iter()
        .all(|key| value.get(key).is_some_and(intervention_string_array))
        && value.get("ref_supported").is_some_and(Value::is_boolean)
}

fn intervention_view_valid(value: &Value) -> bool {
    let identity = value.get("identity");
    let trigger = value.get("trigger");
    let target = value.get("target");
    let reason = value.get("reason");
    let state = value.get("state");
    let execution = state.and_then(|state| state.get("execution"));
    let guards = value.get("guard_tokens");
    let policy = value.get("policy_explanation");
    value.get("format").and_then(Value::as_str) == Some("native.intervention-view.v1")
        && identity.is_some_and(|identity| {
            ["intervention_id", "resolver_database_id", "canonical_url"]
                .into_iter()
                .all(|key| identity.get(key).is_some_and(intervention_nonblank))
        })
        && trigger.is_some_and(|trigger| {
            ["message_id", "summary", "created_at"]
                .into_iter()
                .all(|key| trigger.get(key).is_some_and(intervention_nonblank))
                && trigger
                    .get("message_content_seq")
                    .is_some_and(intervention_positive)
        })
        && target.is_some_and(|target| {
            ["person_record_id", "principal_id"]
                .into_iter()
                .all(|key| target.get(key).is_some_and(intervention_nonblank))
        })
        && value.get("disposition").is_some_and(intervention_nonblank)
        && value
            .get("action_snapshot")
            .is_some_and(intervention_action_snapshot_valid)
        && value.get("request").is_some_and(|request| {
            request.is_null()
                || (request.get("kind").is_some_and(intervention_nonblank)
                    && request
                        .get("action_digest")
                        .is_some_and(intervention_nonblank)
                    && request.get("summary").is_some_and(intervention_nonblank)
                    && request
                        .get("intended_recipient_ids")
                        .is_some_and(intervention_string_array)
                    && request.get("action_digest")
                        == value
                            .get("action_snapshot")
                            .and_then(|snapshot| snapshot.get("action_digest")))
        })
        && reason.is_some_and(|reason| {
            reason.get("summary").is_some_and(intervention_nonblank)
                && reason
                    .get("context_refs")
                    .is_some_and(intervention_string_array)
        })
        && state.is_some_and(intervention_state_valid)
        && execution.is_some_and(|execution| {
            matches!(
                execution.get("state").and_then(Value::as_str),
                Some("proceeded" | "blocked" | "resumed" | "cancelled")
            ) && execution
                .get("basis_event_seq")
                .is_some_and(intervention_positive)
        })
        && guards.is_some_and(|guards| {
            guards
                .get("expected_intervention_seq")
                .is_some_and(intervention_positive)
                && guards
                    .get("expected_evaluation_digest")
                    .is_some_and(intervention_nonblank)
        })
        && policy.is_some_and(|policy| {
            policy.get("trace_digest")
                == guards.and_then(|guards| guards.get("expected_evaluation_digest"))
                && policy.get("disposition") == value.get("disposition")
                && policy
                    .get("reason_codes")
                    .is_some_and(intervention_string_array)
                && policy.get("summary").is_some_and(intervention_nonblank)
        })
        && value.get("projection_seq")
            == guards.and_then(|guards| guards.get("expected_intervention_seq"))
        && value.get("projection_seq")
            == execution.and_then(|execution| execution.get("basis_event_seq"))
        && value.get("lineage").is_some_and(|lineage| {
            ["predecessor_intervention_id", "successor_intervention_id"]
                .into_iter()
                .all(|key| lineage.get(key).is_some_and(intervention_string_or_null))
        })
        && value.get("intended_recipients").is_some_and(|field| {
            field.as_array().is_some_and(|items| {
                items.iter().all(|item| {
                    ["recipient_id", "principal"]
                        .into_iter()
                        .all(|key| item.get(key).is_some_and(intervention_nonblank))
                })
            })
        })
        && value.get("affordances").is_some_and(|field| {
            field
                .as_array()
                .is_some_and(|items| items.iter().all(intervention_affordance_valid))
        })
        && value.get("viewer").is_some_and(intervention_viewer_valid)
        && value.get("raised_at").is_some_and(intervention_nonblank)
}

fn intervention_bounded_line(
    out: &mut String,
    prefix: &str,
    value: &Value,
    remaining: &mut usize,
    cap: usize,
) -> bool {
    if *remaining == 0 {
        return false;
    }
    let encoded = inline_json(value);
    let (preview, shortened) = one_line_preview(&encoded, (*remaining).min(cap));
    *remaining = remaining.saturating_sub(preview.chars().count());
    let _ = writeln!(
        out,
        "{prefix}{preview}{}",
        if shortened {
            " (shortened; exact response remains in structuredContent)"
        } else {
            ""
        }
    );
    true
}

fn intervention_unknowns(
    out: &mut String,
    label: &str,
    value: &Value,
    known: impl Fn(&str) -> bool,
    remaining: &mut usize,
) {
    let unknown = unknown_object_keys(value, known);
    if !unknown.is_empty()
        && intervention_bounded_line(
            out,
            &format!("Additional {label} fields omitted from text: "),
            &json!(unknown),
            remaining,
            800,
        )
    {
        let _ = writeln!(out, "{INTERVENTION_RECOVERY}");
    }
}

fn intervention_typed_line(
    out: &mut String,
    label: &str,
    value: &Value,
    remaining: &mut usize,
    cap: usize,
    known: impl Fn(&str) -> bool + Copy,
    valid: impl Fn(&str, &Value) -> bool + Copy,
) {
    let (projection, malformed) = typed_context_projection(value, known, valid);
    intervention_bounded_line(out, &format!("{label}: "), &projection, remaining, cap);
    if !malformed.is_empty() {
        intervention_bounded_line(
            out,
            &format!("Malformed {label} fields omitted: "),
            &json!(malformed),
            remaining,
            600,
        );
    }
    intervention_unknowns(out, label, value, known, remaining);
}

fn intervention_typed_array(
    out: &mut String,
    label: &str,
    values: &[Value],
    remaining: &mut usize,
    cap: usize,
    known: impl Fn(&str) -> bool + Copy,
    valid: impl Fn(&str, &Value) -> bool + Copy,
) {
    let mut rendered = 0usize;
    let mut malformed = 0usize;
    for value in values.iter().take(INTERVENTION_ITEM_LIMIT) {
        if !value.is_object() {
            malformed += 1;
            continue;
        }
        let before = *remaining;
        intervention_typed_line(out, label, value, remaining, cap, known, valid);
        if *remaining < before {
            rendered += 1;
        }
    }
    if rendered + malformed < values.len() || malformed > 0 {
        let _ = writeln!(
            out,
            "{label} detail: {rendered} rendered, {malformed} malformed, {} omitted from text; {INTERVENTION_RECOVERY}",
            values.len().saturating_sub(rendered + malformed)
        );
    }
}

fn render_intervention_view(value: &Value, include_heading: bool) -> String {
    let mut remaining = INTERVENTION_TEXT_BUDGET;
    render_intervention_view_with_budget(value, include_heading, &mut remaining)
}

fn render_intervention_view_with_budget(
    value: &Value,
    include_heading: bool,
    budget: &mut usize,
) -> String {
    if !intervention_view_valid(value) {
        return format!(
            "Intervention view is malformed and was not interpreted; {INTERVENTION_RECOVERY}\n"
        );
    }
    let id = value.pointer("/identity/intervention_id").unwrap();
    let execution = value.pointer("/state/execution/state").unwrap();
    let mut out = if include_heading {
        format!(
            "Intervention {}: {}.\n",
            inline_json(id),
            inline_json(execution)
        )
    } else {
        String::new()
    };
    let mut remaining = (*budget).saturating_sub(out.chars().count());
    if execution.as_str() == Some("blocked") {
        intervention_bounded_line(
            &mut out,
            "Cancel guard arguments: ",
            &json!({"expected_intervention_seq":value["guard_tokens"]["expected_intervention_seq"]}),
            &mut remaining,
            500,
        );
        intervention_bounded_line(
            &mut out,
            "Resume-delivery guard arguments: ",
            &value["guard_tokens"],
            &mut remaining,
            800,
        );
    }
    intervention_bounded_line(
        &mut out,
        "Action controls: ",
        &json!({"requested_outcome":value["action_snapshot"]["requested_outcome"],"action_digest":value["action_snapshot"]["action_digest"]}),
        &mut remaining,
        1_000,
    );
    let action = &value["action_snapshot"]["action"];
    let (action_projection, action_malformed) = typed_context_projection(
        action,
        |key| {
            matches!(
                key,
                "class"
                    | "operation"
                    | "destination_kind"
                    | "destination_workspace_id"
                    | "reversible"
                    | "sensitivity"
                    | "correspondent_principal_ids"
                    | "disclosure_preview"
            )
        },
        |key, field| match key {
            "reversible" => field.is_boolean(),
            "correspondent_principal_ids" => intervention_string_array(field),
            "disclosure_preview" => intervention_string_or_null(field),
            _ => intervention_nonblank(field),
        },
    );
    intervention_bounded_line(
        &mut out,
        "Frozen action: ",
        &action_projection,
        &mut remaining,
        3_000,
    );
    if !action_malformed.is_empty() {
        intervention_bounded_line(
            &mut out,
            "Malformed frozen-action fields omitted: ",
            &json!(action_malformed),
            &mut remaining,
            600,
        );
    }
    intervention_unknowns(
        &mut out,
        "frozen-action",
        action,
        |key| {
            matches!(
                key,
                "class"
                    | "operation"
                    | "destination_kind"
                    | "destination_workspace_id"
                    | "reversible"
                    | "sensitivity"
                    | "correspondent_principal_ids"
                    | "disclosure_preview"
            )
        },
        &mut remaining,
    );
    intervention_typed_line(
        &mut out,
        "Identity",
        &value["identity"],
        &mut remaining,
        1_500,
        |key| {
            matches!(
                key,
                "intervention_id" | "resolver_database_id" | "canonical_url"
            )
        },
        |_, field| intervention_nonblank(field),
    );
    intervention_typed_line(
        &mut out,
        "Lineage",
        &value["lineage"],
        &mut remaining,
        800,
        |key| {
            matches!(
                key,
                "predecessor_intervention_id" | "successor_intervention_id"
            )
        },
        |_, field| intervention_string_or_null(field),
    );
    intervention_typed_line(
        &mut out,
        "Trigger",
        &value["trigger"],
        &mut remaining,
        2_500,
        |key| {
            matches!(
                key,
                "message_id" | "message_content_seq" | "summary" | "created_at"
            )
        },
        |key, field| {
            if key == "message_content_seq" {
                intervention_positive(field)
            } else {
                intervention_nonblank(field)
            }
        },
    );
    intervention_typed_line(
        &mut out,
        "Target",
        &value["target"],
        &mut remaining,
        1_000,
        |key| matches!(key, "person_record_id" | "principal_id"),
        |_, field| intervention_nonblank(field),
    );
    intervention_typed_line(
        &mut out,
        "Reason",
        &value["reason"],
        &mut remaining,
        2_500,
        |key| matches!(key, "summary" | "context_refs"),
        |key, field| {
            if key == "context_refs" {
                intervention_string_array(field)
            } else {
                intervention_nonblank(field)
            }
        },
    );
    if value["request"].is_object() {
        intervention_typed_line(
            &mut out,
            "Request",
            &value["request"],
            &mut remaining,
            2_500,
            |key| {
                matches!(
                    key,
                    "kind" | "action_digest" | "summary" | "intended_recipient_ids"
                )
            },
            |key, field| {
                if key == "intended_recipient_ids" {
                    intervention_string_array(field)
                } else {
                    intervention_nonblank(field)
                }
            },
        );
    } else {
        intervention_bounded_line(&mut out, "Request: ", &Value::Null, &mut remaining, 100);
    }
    intervention_typed_line(
        &mut out,
        "Attention state",
        &value["state"]["attention"],
        &mut remaining,
        700,
        |key| matches!(key, "state" | "source_format"),
        |key, field| {
            if key == "source_format" {
                intervention_string_or_null(field)
            } else {
                intervention_nonblank(field)
            }
        },
    );
    let obligation = &value["state"]["obligation"];
    let mut obligation_summary = obligation.clone();
    obligation_summary
        .as_object_mut()
        .expect("validated obligation object")
        .remove("evidence");
    intervention_typed_line(
        &mut out,
        "Obligation state (independently live at read time)",
        &obligation_summary,
        &mut remaining,
        1_500,
        |key| {
            matches!(
                key,
                "format" | "message_id" | "recipient_id" | "expectation" | "state"
            )
        },
        |key, field| match key {
            "expectation" => intervention_string_or_null(field),
            _ => intervention_nonblank(field),
        },
    );
    if value["state"]["obligation"]["evidence"].is_object() {
        intervention_typed_line(
            &mut out,
            "Obligation evidence",
            &value["state"]["obligation"]["evidence"],
            &mut remaining,
            800,
            |key| matches!(key, "kind" | "record_id"),
            |_, field| intervention_nonblank(field),
        );
    }
    intervention_unknowns(
        &mut out,
        "obligation-state",
        obligation,
        |key| {
            matches!(
                key,
                "format" | "message_id" | "recipient_id" | "expectation" | "state" | "evidence"
            )
        },
        &mut remaining,
    );
    intervention_typed_line(
        &mut out,
        "Execution state",
        &value["state"]["execution"],
        &mut remaining,
        700,
        |key| matches!(key, "state" | "basis_event_seq"),
        |key, field| {
            if key == "basis_event_seq" {
                intervention_positive(field)
            } else {
                intervention_nonblank(field)
            }
        },
    );
    intervention_typed_line(
        &mut out,
        "Timing state",
        &value["state"]["timing"],
        &mut remaining,
        700,
        |key| matches!(key, "state" | "respond_by"),
        |key, field| {
            if key == "respond_by" {
                intervention_string_or_null(field)
            } else {
                intervention_nonblank(field)
            }
        },
    );
    intervention_unknowns(
        &mut out,
        "intervention-state",
        &value["state"],
        |key| matches!(key, "attention" | "obligation" | "execution" | "timing"),
        &mut remaining,
    );
    intervention_typed_line(
        &mut out,
        "Policy explanation",
        &value["policy_explanation"],
        &mut remaining,
        2_000,
        |key| {
            matches!(
                key,
                "trace_digest" | "disposition" | "reason_codes" | "summary"
            )
        },
        |key, field| {
            if key == "reason_codes" {
                intervention_string_array(field)
            } else {
                intervention_nonblank(field)
            }
        },
    );
    intervention_typed_array(
        &mut out,
        "Intended recipient",
        value["intended_recipients"].as_array().unwrap(),
        &mut remaining,
        600,
        |key| matches!(key, "recipient_id" | "principal"),
        |_, field| intervention_nonblank(field),
    );
    intervention_typed_array(
        &mut out,
        "Affordance",
        value["affordances"].as_array().unwrap(),
        &mut remaining,
        600,
        |key| matches!(key, "kind" | "enabled" | "reason_code"),
        |key, field| match key {
            "enabled" => field.is_boolean(),
            "reason_code" => intervention_string_or_null(field),
            _ => intervention_nonblank(field),
        },
    );
    intervention_typed_line(
        &mut out,
        "Viewer capabilities",
        &value["viewer"],
        &mut remaining,
        1_500,
        |key| {
            matches!(
                key,
                "intent_format"
                    | "supported_focus"
                    | "supported_evidence"
                    | "supported_controls"
                    | "ref_supported"
            )
        },
        |key, field| match key {
            "supported_focus" | "supported_evidence" | "supported_controls" => {
                intervention_string_array(field)
            }
            "ref_supported" => field.is_boolean(),
            _ => intervention_nonblank(field),
        },
    );
    intervention_bounded_line(
        &mut out,
        "Raised at: ",
        &value["raised_at"],
        &mut remaining,
        500,
    );
    intervention_unknowns(
        &mut out,
        "intervention-view",
        value,
        |key| {
            matches!(
                key,
                "action"
                    | "format"
                    | "identity"
                    | "lineage"
                    | "trigger"
                    | "target"
                    | "disposition"
                    | "action_snapshot"
                    | "request"
                    | "reason"
                    | "state"
                    | "policy_explanation"
                    | "intended_recipients"
                    | "affordances"
                    | "viewer"
                    | "guard_tokens"
                    | "projection_seq"
                    | "raised_at"
                    | "write_receipt"
                    | "run_context"
            )
        },
        &mut remaining,
    );
    if remaining == 0 {
        let _ = writeln!(
            out,
            "Intervention text budget reached its limit; {INTERVENTION_RECOVERY}"
        );
    }
    *budget = remaining;
    out
}

fn render_intervention_write(value: &Value, action: &str) -> String {
    if !intervention_view_valid(value) {
        return format!("Intervention {action} response is malformed and no write outcome was inferred; {INTERVENTION_RECOVERY}\n");
    }
    let Some(receipt) = value.get("write_receipt").and_then(Value::as_object) else {
        return format!("Intervention {action} response has no valid write receipt and no write outcome was inferred; {INTERVENTION_RECOVERY}\n");
    };
    let expected_status = if action == "cancel" {
        "cancelled"
    } else {
        "resumed"
    };
    let expected_event = if action == "cancel" {
        "intervention.cancelled.v1"
    } else {
        "intervention.execution_resumed.v1"
    };
    let terminal = receipt.get("terminal_event");
    let transition = receipt.get("transition");
    let common_valid = receipt.get("status").and_then(Value::as_str) == Some(expected_status)
        && receipt.get("replayed").is_some_and(Value::is_boolean)
        && value
            .pointer("/state/execution/state")
            .and_then(Value::as_str)
            == Some(expected_status)
        && if action == "cancel" {
            receipt.get("delivery_event_id").is_some_and(Value::is_null)
        } else {
            receipt
                .get("delivery_event_id")
                .is_some_and(intervention_nonblank)
        }
        && terminal.is_some_and(|event| {
            ["record_id", "event_id", "type"]
                .into_iter()
                .all(|key| event.get(key).is_some_and(intervention_nonblank))
                && event.get("seq").is_some_and(intervention_positive)
                && event.get("type").and_then(Value::as_str) == Some(expected_event)
                && event.get("record_id")
                    == value
                        .get("trigger")
                        .and_then(|trigger| trigger.get("message_id"))
                && event.get("seq") == value.get("projection_seq")
                && event.get("seq") == value.pointer("/state/execution/basis_event_seq")
        });
    let transition_valid = transition.is_some_and(|transition| {
        if action == "cancel" {
            ["action_digest", "idempotency_key", "reason"]
                .into_iter()
                .all(|key| transition.get(key).is_some_and(intervention_nonblank))
                && transition
                    .get("evidence_refs")
                    .is_some_and(intervention_string_array)
                && transition.get("action_digest")
                    == value
                        .get("action_snapshot")
                        .and_then(|snapshot| snapshot.get("action_digest"))
        } else {
            [
                "basis_kind",
                "basis_record_id",
                "action_digest",
                "delivery_event_id",
                "fresh_evaluation_digest",
                "idempotency_key",
                "summary",
            ]
            .into_iter()
            .all(|key| transition.get(key).is_some_and(intervention_nonblank))
                && receipt.get("delivery_event_id") == transition.get("delivery_event_id")
                && transition.get("basis_kind").and_then(Value::as_str)
                    == Some("authority_evidence")
                && transition.get("action_digest")
                    == value
                        .get("action_snapshot")
                        .and_then(|snapshot| snapshot.get("action_digest"))
        }
    });
    if !common_valid || !transition_valid {
        return format!("Intervention {action} write receipt is malformed and no write outcome was inferred; {INTERVENTION_RECOVERY}\n");
    }
    let replayed = receipt["replayed"].as_bool().unwrap();
    let mut out = format!(
        "Intervention {action} write receipt: {}.\n",
        if replayed {
            "idempotent replay; no new write was performed by this call"
        } else {
            "applied"
        }
    );
    let mut remaining = INTERVENTION_TEXT_BUDGET.saturating_sub(out.chars().count());
    intervention_typed_line(
        &mut out,
        "Terminal event",
        terminal.unwrap(),
        &mut remaining,
        1_500,
        |key| matches!(key, "record_id" | "event_id" | "seq" | "type"),
        |key, field| {
            if key == "seq" {
                intervention_positive(field)
            } else {
                intervention_nonblank(field)
            }
        },
    );
    if action == "cancel" {
        intervention_typed_line(
            &mut out,
            "Transition",
            transition.unwrap(),
            &mut remaining,
            4_000,
            |key| {
                matches!(
                    key,
                    "action_digest" | "idempotency_key" | "reason" | "evidence_refs"
                )
            },
            |key, field| {
                if key == "evidence_refs" {
                    intervention_string_array(field)
                } else {
                    intervention_nonblank(field)
                }
            },
        );
    } else {
        intervention_typed_line(
            &mut out,
            "Transition",
            transition.unwrap(),
            &mut remaining,
            4_000,
            |key| {
                matches!(
                    key,
                    "basis_kind"
                        | "basis_record_id"
                        | "action_digest"
                        | "delivery_event_id"
                        | "fresh_evaluation_digest"
                        | "idempotency_key"
                        | "summary"
                )
            },
            |_, field| intervention_nonblank(field),
        );
    }
    intervention_unknowns(
        &mut out,
        "write-receipt",
        &Value::Object(receipt.clone()),
        |key| {
            matches!(
                key,
                "status" | "replayed" | "terminal_event" | "transition" | "delivery_event_id"
            )
        },
        &mut remaining,
    );
    out.push_str(&render_intervention_view_with_budget(
        value,
        false,
        &mut remaining,
    ));
    out
}

fn render_intervention_query(value: &Value) -> String {
    let items = value.get("items").and_then(Value::as_array);
    let count = value.get("count").and_then(Value::as_u64);
    let limit = value.get("limit").and_then(Value::as_u64);
    let has_more = value.get("has_more").and_then(Value::as_bool);
    let next_cursor = value.get("next_cursor");
    let scan_limit = value.get("candidate_scan_limit").and_then(Value::as_u64);
    let window_returned = value
        .get("candidate_window_returned")
        .and_then(Value::as_u64);
    let candidates_evaluated = value.get("candidates_evaluated").and_then(Value::as_u64);
    let scan_reached = value.get("scan_limit_reached").and_then(Value::as_bool);
    let valid = value.get("format").and_then(Value::as_str) == Some("native.intervention-query.v1")
        && value.get("viewer_relative").and_then(Value::as_bool) == Some(true)
        && value.get("query_basis").and_then(Value::as_str) == Some("live_at_each_page_read")
        && items.is_some_and(|items| {
            items.len() <= INTERVENTION_ITEM_LIMIT && items.iter().all(intervention_view_valid)
        })
        && count == items.map(|items| items.len() as u64)
        && limit.is_some_and(|limit| (1..=50).contains(&limit))
        && count
            .zip(limit)
            .is_some_and(|(count, limit)| count <= limit)
        && has_more.is_some()
        && has_more
            == next_cursor.map(|cursor| {
                cursor
                    .as_str()
                    .is_some_and(|cursor| !cursor.trim().is_empty())
            })
        && scan_limit == Some(200)
        && window_returned.is_some_and(|returned| returned <= 200)
        && candidates_evaluated.is_some_and(|evaluated| evaluated <= 200)
        && candidates_evaluated
            .zip(window_returned)
            .is_some_and(|(evaluated, returned)| evaluated <= returned)
        && candidates_evaluated
            .zip(count)
            .is_some_and(|(evaluated, count)| evaluated >= count)
        && scan_reached.is_some()
        && (!scan_reached.unwrap_or(false) || window_returned == Some(200))
        && value.get("execution").is_some_and(|field| {
            field.is_null()
                || matches!(
                    field.as_str(),
                    Some("proceeded" | "blocked" | "resumed" | "cancelled")
                )
        });
    if !valid {
        return format!("Intervention query response is malformed and no page claim was inferred; {INTERVENTION_RECOVERY}\n");
    }
    let items = items.unwrap();
    let mut out = format!(
        "Intervention query returned {} live viewer-relative item(s).\n",
        items.len()
    );
    let mut remaining = INTERVENTION_TEXT_BUDGET;
    intervention_bounded_line(
        &mut out,
        "Page controls: ",
        &json!({"execution":value["execution"],"limit":value["limit"],"has_more":value["has_more"],"candidate_window_limit":value["candidate_scan_limit"],"candidate_window_returned":value["candidate_window_returned"],"candidates_evaluated":value["candidates_evaluated"],"candidate_window_has_more":value["scan_limit_reached"]}),
        &mut remaining,
        1_500,
    );
    if has_more == Some(true) {
        intervention_bounded_line(
            &mut out,
            "Next query arguments: ",
            &json!({"action":"query","execution":value["execution"],"limit":value["limit"],"cursor":value["next_cursor"]}),
            &mut remaining,
            1_500,
        );
    } else {
        out.push_str("No continuation cursor was issued; raised candidates below this page boundary were exhausted at this live read.\n");
    }
    out.push_str("Pages are evaluated live; this is not a frozen cross-page snapshot.\n");
    for item in items {
        let compact = json!({
            "intervention_id":item["identity"]["intervention_id"],
            "execution":item["state"]["execution"]["state"],
            "disposition":item["disposition"],
            "summary":item["trigger"]["summary"],
            "raised_at":item["raised_at"],
            "guard_tokens":item["guard_tokens"],
            "action_digest":item["action_snapshot"]["action_digest"],
        });
        if !intervention_bounded_line(
            &mut out,
            "- Compact query row: ",
            &compact,
            &mut remaining,
            1_200,
        ) {
            break;
        }
        intervention_bounded_line(
            &mut out,
            "  Get full current view with arguments: ",
            &json!({"action":"get","intervention_id":item["identity"]["intervention_id"]}),
            &mut remaining,
            800,
        );
        intervention_unknowns(
            &mut out,
            "query item",
            item,
            |key| {
                matches!(
                    key,
                    "format"
                        | "identity"
                        | "lineage"
                        | "trigger"
                        | "target"
                        | "disposition"
                        | "action_snapshot"
                        | "request"
                        | "reason"
                        | "state"
                        | "policy_explanation"
                        | "intended_recipients"
                        | "affordances"
                        | "viewer"
                        | "guard_tokens"
                        | "projection_seq"
                        | "raised_at"
                )
            },
            &mut remaining,
        );
        intervention_unknowns(
            &mut out,
            "query-item identity",
            &item["identity"],
            |key| {
                matches!(
                    key,
                    "intervention_id" | "resolver_database_id" | "canonical_url"
                )
            },
            &mut remaining,
        );
        intervention_unknowns(
            &mut out,
            "query-item trigger",
            &item["trigger"],
            |key| {
                matches!(
                    key,
                    "message_id" | "message_content_seq" | "summary" | "created_at"
                )
            },
            &mut remaining,
        );
        intervention_unknowns(
            &mut out,
            "query-item execution",
            &item["state"]["execution"],
            |key| matches!(key, "state" | "basis_event_seq"),
            &mut remaining,
        );
        intervention_unknowns(
            &mut out,
            "query-item guards",
            &item["guard_tokens"],
            |key| {
                matches!(
                    key,
                    "expected_intervention_seq" | "expected_evaluation_digest"
                )
            },
            &mut remaining,
        );
        intervention_unknowns(
            &mut out,
            "query-item action snapshot",
            &item["action_snapshot"],
            |key| matches!(key, "requested_outcome" | "action" | "action_digest"),
            &mut remaining,
        );
    }
    intervention_unknowns(
        &mut out,
        "intervention-query",
        value,
        |key| {
            matches!(
                key,
                "action"
                    | "format"
                    | "items"
                    | "count"
                    | "viewer_relative"
                    | "execution"
                    | "limit"
                    | "has_more"
                    | "next_cursor"
                    | "candidate_scan_limit"
                    | "candidate_window_returned"
                    | "candidates_evaluated"
                    | "scan_limit_reached"
                    | "query_basis"
                    | "run_context"
            )
        },
        &mut remaining,
    );
    if remaining == 0 {
        let _ = writeln!(
            out,
            "Intervention-query text budget reached its limit; {INTERVENTION_RECOVERY}"
        );
    }
    out
}

fn render_identity_operation(label: &str, value: &Value) -> String {
    let Some(status) = string(value, "status") else {
        return format!(
            "{label} response is missing its status; no outcome was inferred. Exact response: {}\n",
            inline_json(value)
        );
    };
    let Some(record) = string(value, "record_id") else {
        return format!(
            "{label} response is missing its record identity; no outcome was inferred. Exact response: {}\n",
            inline_json(value)
        );
    };
    let mut out = format!("{label}: {status} for {record}.");
    if let Some(observation) = string(value, "observation_id") {
        let _ = write!(out, " Observation {observation}.");
    }
    if let Some(attachment) = string(value, "attachment_id") {
        let _ = write!(out, " Snapshot attachment {attachment}.");
    }
    if let Some(provenance) = value.get("provenance") {
        // Each of these words is also a value the producer can assert, so a
        // default would make "we were told nothing" indistinguishable from
        // "the source told us it is unknown / none / not attempted".
        let freshness = claimed_string(provenance.get("freshness"), "freshness");
        let retention = claimed_string(provenance.get("retention_state"), "retention_state");
        let availability =
            claimed_string(provenance.get("source_availability"), "source_availability");
        let refresh = claimed_string(provenance.get("refresh_outcome"), "refresh_outcome");
        let _ = write!(
            out,
            " Provenance: {freshness}/{retention}; source {availability}; refresh {refresh}."
        );
        if let Some(revision) = string(provenance, "source_revision") {
            let _ = write!(out, " Source revision {revision}.");
        }
        if let Some(digest) = string(provenance, "source_digest") {
            let _ = write!(out, " Source digest {digest}.");
        }
        if let Some(retained_from) = string(provenance, "retained_from_observation_id") {
            let _ = write!(out, " Retained from observation {retained_from}.");
        }
    }
    out.push('\n');
    // Identity responses are small, handler-bounded receipts. Preserve every
    // action-specific value rather than making this shared renderer guess at
    // the union: list/observations carry their complete rows, reconciliation
    // carries both endpoints and selected bindings, and resolve/observe carry
    // materialization facts that are part of the result rather than prose
    // decoration. A future top-level field therefore fails safe into text.
    render_fields(
        &mut out,
        value,
        &[
            "status",
            "record_id",
            "observation_id",
            "attachment_id",
            "run_context",
        ],
    );
    out
}

const SET_INTENT_DETAIL_BUDGET: usize = 24_000;
const SET_INTENT_ACTIVE_SECTION_BUDGET: usize = 6_000;
const SET_INTENT_WRITE_RECOVERY: &str = "Exact response remains in structuredContent; a new set_intent call is not an exact replay and must not be made solely to obtain another format.";

#[derive(Clone, Copy)]
enum IntentWindowKind {
    Declaration,
    Record,
    Lineage,
    Claim,
}

fn intent_item_projection(kind: IntentWindowKind, item: &Value) -> Value {
    let pick = |keys: &[&str]| {
        Value::Object(
            item.as_object()
                .into_iter()
                .flatten()
                .filter(|(key, _)| keys.contains(&key.as_str()))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        )
    };
    match kind {
        IntentWindowKind::Declaration => {
            let mut projected = pick(&["intent", "declared_at"]);
            if let Some(touched) = item
                .get("touched_records")
                .filter(|value| value.is_object())
            {
                let unknown = unknown_object_keys(touched, |key| {
                    matches!(key, "items" | "total_count" | "truncated")
                });
                let returned = array(touched, "items").len();
                projected
                    .as_object_mut()
                    .expect("projection is an object")
                    .insert(
                        "touched_records".into(),
                        json!({
                            "returned": returned,
                            "total_count": touched.get("total_count"),
                            "truncated": touched.get("truncated"),
                        }),
                    );
                if returned > 0 {
                    projected
                        .as_object_mut()
                        .expect("projection is an object")
                        .insert(
                            "touched_records_text".into(),
                            json!("items summarized; exact current items remain in structuredContent; a new set_intent call is not an exact replay"),
                        );
                }
                if !unknown.is_empty() {
                    projected
                        .as_object_mut()
                        .expect("projection is an object")
                        .insert("additional_touched_record_fields".into(), json!(unknown));
                }
            } else if item.get("touched_records").is_some() {
                projected
                    .as_object_mut()
                    .expect("projection is an object")
                    .insert(
                        "touched_records_text".into(),
                        json!("malformed and not interpreted; exact current value remains in structuredContent; a new set_intent call is not an exact replay"),
                    );
            }
            projected
        }
        IntentWindowKind::Record => {
            let mut projected = pick(&[
                "id",
                "name",
                "type",
                "lifecycle",
                "last_touched_at",
                "reason",
            ]);
            if let Some(interactions) = item.get("interactions").filter(|value| value.is_object()) {
                let unknown = unknown_object_keys(interactions, |key| {
                    matches!(key, "surfaced" | "opened" | "mutated")
                });
                projected
                    .as_object_mut()
                    .expect("projection is an object")
                    .insert(
                        "interactions".into(),
                        Value::Object(
                            interactions
                                .as_object()
                                .into_iter()
                                .flatten()
                                .filter(|(key, _)| {
                                    matches!(key.as_str(), "surfaced" | "opened" | "mutated")
                                })
                                .map(|(key, value)| (key.clone(), value.clone()))
                                .collect(),
                        ),
                    );
                if !unknown.is_empty() {
                    projected
                        .as_object_mut()
                        .expect("projection is an object")
                        .insert("additional_interaction_fields".into(), json!(unknown));
                }
            } else if item.get("interactions").is_some() {
                projected
                    .as_object_mut()
                    .expect("projection is an object")
                    .insert(
                        "interactions_text".into(),
                        json!("malformed and not interpreted; exact current value remains in structuredContent; a new set_intent call is not an exact replay"),
                    );
            }
            projected
        }
        IntentWindowKind::Lineage => pick(&["run_key", "intent"]),
        IntentWindowKind::Claim => pick(&["id", "name", "type", "claimed_at", "run_key"]),
    }
}

fn intent_item_known(kind: IntentWindowKind, key: &str) -> bool {
    match kind {
        IntentWindowKind::Declaration => {
            matches!(key, "intent" | "declared_at" | "touched_records")
        }
        IntentWindowKind::Record => matches!(
            key,
            "id" | "name" | "type" | "lifecycle" | "interactions" | "last_touched_at" | "reason"
        ),
        IntentWindowKind::Lineage => matches!(key, "run_key" | "intent"),
        IntentWindowKind::Claim => {
            matches!(key, "id" | "name" | "type" | "claimed_at" | "run_key")
        }
    }
}

fn render_intent_window(
    out: &mut String,
    label: &str,
    window: Option<&Value>,
    remaining: &mut usize,
    bounded_candidate_scan: bool,
    kind: IntentWindowKind,
    extra_window_key: Option<&str>,
) {
    let Some(window) = window.filter(|value| value.is_object()) else {
        let _ = writeln!(out, "{label}: unavailable in this briefing.");
        return;
    };
    let Some(items) = window.get("items").and_then(Value::as_array) else {
        let _ = writeln!(out, "{label}: item window unavailable or malformed.");
        return;
    };
    let total = window.get("total_count").and_then(Value::as_u64);
    let truncated = boolean(window, "truncated");
    match (total, truncated) {
        (Some(total), Some(truncated)) if bounded_candidate_scan => {
            let _ = write!(
                out,
                "{label}: {} returned; {total} qualifying item(s) found in the bounded candidate scan",
                items.len()
            );
            if truncated {
                out.push_str(
                    "; the scan or returned page was truncated and additional items may exist",
                );
            }
            out.push_str(".\n");
        }
        (Some(total), Some(truncated)) => {
            let _ = write!(out, "{label}: {} returned of {total}", items.len());
            if truncated {
                if matches!(kind, IntentWindowKind::Lineage) {
                    out.push_str("; lineage path truncated");
                } else {
                    out.push_str("; producer window truncated and additional authorized items exist or may exist");
                }
            }
            out.push_str(".\n");
        }
        _ => {
            let _ = writeln!(
                out,
                "{label}: window metadata unavailable; {} item(s) returned.",
                items.len()
            );
        }
    }

    let mut rendered = 0usize;
    let mut malformed = 0usize;
    for (index, item) in items.iter().enumerate() {
        if !item.is_object() {
            let _ = writeln!(
                out,
                "- {label} item {} is malformed and was not interpreted; its exact current value remains in structuredContent and a new set_intent call is not an exact replay.",
                index + 1
            );
            malformed += 1;
            continue;
        }
        let projected = intent_item_projection(kind, item);
        if !render_bounded_query_json_line(
            out,
            "- ",
            &projected,
            remaining,
            " (shortened; exact current value remains in structuredContent; a new set_intent call is not an exact replay)",
        ) {
            break;
        }
        rendered += 1;
        let unknown = unknown_object_keys(item, |key| intent_item_known(kind, key));
        if !unknown.is_empty() {
            let _ = writeln!(
                out,
                "  Additional {label} item fields omitted from text: {}; {SET_INTENT_WRITE_RECOVERY}",
                inline_json(&json!(unknown)),
            );
        }
    }
    if rendered + malformed < items.len() {
        let _ = writeln!(
            out,
            "  {label} detail budget exhausted: {rendered} of {} interpretable returned item(s) rendered; exact current values remain in structuredContent and a new set_intent call is not an exact replay.",
            items.len()
        );
    }
    let unknown = unknown_object_keys(window, |key| {
        matches!(key, "items" | "total_count" | "truncated") || extra_window_key == Some(key)
    });
    if !unknown.is_empty() {
        let _ = writeln!(
            out,
            "  Additional {label} fields omitted from text: {}; {SET_INTENT_WRITE_RECOVERY}",
            inline_json(&json!(unknown)),
        );
    }
}

fn render_set_intent(value: &Value) -> String {
    let mut out = String::new();
    match string(value, "accepted_intent") {
        Some(accepted) => {
            let (preview, shortened) = one_line_preview(&accepted, 500);
            let _ = writeln!(out, "Intent accepted: {}", display_inline(&preview));
            if shortened {
                out.push_str("Accepted intent shortened for text; exact current value remains in structuredContent and a new set_intent call is not an exact replay.\n");
            }
        }
        None => {
            let _ = writeln!(
                out,
                "Intent acceptance field unavailable; {SET_INTENT_WRITE_RECOVERY}"
            );
        }
    }
    if let Some(attestations) = value.get("action_attestation_ids") {
        let _ = writeln!(out, "Action attestations: {}", inline_json(attestations));
    }
    let unknown = unknown_object_keys(value, |key| {
        matches!(
            key,
            "accepted_intent"
                | "briefing_version"
                | "briefing"
                | "run_context"
                | "action_attestation_ids"
        )
    });
    if !unknown.is_empty() {
        let _ = writeln!(
            out,
            "Additional set_intent fields omitted from text: {}; {SET_INTENT_WRITE_RECOVERY}",
            inline_json(&json!(unknown)),
        );
    }

    let Some(version) = integer(value, "briefing_version") else {
        let _ = writeln!(
            out,
            "\nBriefing version unavailable; details cannot be interpreted safely in text. {SET_INTENT_WRITE_RECOVERY}",
        );
        return out;
    };
    let briefing = value.get("briefing").unwrap_or(&Value::Null);
    let _ = writeln!(out, "\nBriefing v{version}");
    let unknown = unknown_object_keys(briefing, |key| {
        matches!(
            key,
            "availability" | "this_run" | "resume" | "working_under" | "open_claims"
        )
    });
    if !unknown.is_empty() {
        let _ = writeln!(
            out,
            "Additional briefing fields omitted from text: {}; {SET_INTENT_WRITE_RECOVERY}",
            inline_json(&json!(unknown)),
        );
    }
    if version != 1 {
        out.push_str("This briefing version is unsupported by the text renderer; exact current values remain in structuredContent and a new set_intent call is not an exact replay.\n");
        return out;
    }

    let availability = briefing.get("availability").unwrap_or(&Value::Null);
    let availability_unknown =
        unknown_object_keys(availability, |key| matches!(key, "status" | "reason"));
    if !availability_unknown.is_empty() {
        let _ = writeln!(
            out,
            "Additional availability fields omitted from text: {}; {SET_INTENT_WRITE_RECOVERY}",
            inline_json(&json!(availability_unknown)),
        );
    }
    let availability_status = string(availability, "status");
    if availability_status.as_deref() != Some("available") {
        let reason =
            string(availability, "reason").unwrap_or_else(|| "missing_discriminator".into());
        let _ = writeln!(
            out,
            "Briefing unavailable: {}. Resume, lineage, and claims were not assessed; zero/none must not be inferred.",
            display_inline(&reason)
        );
        if availability_status.is_none() {
            let _ = writeln!(out, "{SET_INTENT_WRITE_RECOVERY}");
        }
        return out;
    }
    out.push_str("Briefing availability: available.\n");

    if let Some(this_run) = briefing.get("this_run") {
        let unknown = unknown_object_keys(this_run, |key| key == "declarations");
        if !unknown.is_empty() {
            let _ = writeln!(
                out,
                "Additional this-run fields omitted from text: {}; {SET_INTENT_WRITE_RECOVERY}",
                inline_json(&json!(unknown)),
            );
        }
    }

    let mut lineage_remaining = SET_INTENT_ACTIVE_SECTION_BUDGET;
    let mut claims_remaining = SET_INTENT_ACTIVE_SECTION_BUDGET;
    let mut remaining = SET_INTENT_DETAIL_BUDGET
        .saturating_sub(lineage_remaining)
        .saturating_sub(claims_remaining);
    // Active coordination facts come first: they prevent collisions and
    // explain the current run even when later historical detail exhausts the
    // shared rendering budget.
    let working_under = briefing.get("working_under");
    render_intent_window(
        &mut out,
        "Working under",
        working_under,
        &mut lineage_remaining,
        false,
        IntentWindowKind::Lineage,
        Some("end"),
    );
    if let Some(working_under) = working_under {
        let end = working_under
            .get("end")
            .map(inline_json)
            .unwrap_or_else(|| "<unavailable>".into());
        let truncated = boolean(working_under, "truncated");
        let completeness = if truncated == Some(false) && end == "\"rooted\"" {
            "complete rooted path"
        } else {
            "incomplete or non-rooted path"
        };
        let _ = writeln!(out, "Working-under end: {end} ({completeness}).");
    }
    render_intent_window(
        &mut out,
        "Open claims",
        briefing.get("open_claims"),
        &mut claims_remaining,
        true,
        IntentWindowKind::Claim,
        None,
    );
    render_intent_window(
        &mut out,
        "This run declarations",
        briefing.pointer("/this_run/declarations"),
        &mut remaining,
        false,
        IntentWindowKind::Declaration,
        None,
    );

    if let Some(resume) = briefing.get("resume").filter(|value| value.is_object()) {
        let metadata = exact_known_object_remainder(resume, &[], |key| {
            matches!(key, "run_key" | "started_at" | "ended_at" | "duration_ms")
        });
        if let Some(metadata) = metadata {
            let _ = writeln!(out, "Resume metadata: {}", inline_json(&metadata));
        } else {
            out.push_str("Resume metadata: unavailable.\n");
        }
        let unknown = unknown_object_keys(resume, |key| {
            matches!(
                key,
                "run_key"
                    | "started_at"
                    | "ended_at"
                    | "duration_ms"
                    | "declarations"
                    | "touched_records"
                    | "left_non_terminal"
                    | "unclassified_lifecycle"
            )
        });
        if !unknown.is_empty() {
            let _ = writeln!(
                out,
                "Additional resume fields omitted from text: {}; {SET_INTENT_WRITE_RECOVERY}",
                inline_json(&json!(unknown)),
            );
        }
        // Actionable continuation state is rendered before declaration history
        // so a saturated declaration window cannot consume the shared budget.
        render_intent_window(
            &mut out,
            "Resume left non-terminal",
            resume.get("left_non_terminal"),
            &mut remaining,
            false,
            IntentWindowKind::Record,
            None,
        );
        render_intent_window(
            &mut out,
            "Resume unclassified lifecycle",
            resume.get("unclassified_lifecycle"),
            &mut remaining,
            false,
            IntentWindowKind::Record,
            None,
        );
        render_intent_window(
            &mut out,
            "Resume touched records",
            resume.get("touched_records"),
            &mut remaining,
            false,
            IntentWindowKind::Record,
            None,
        );
        render_intent_window(
            &mut out,
            "Resume declarations",
            resume.get("declarations"),
            &mut remaining,
            false,
            IntentWindowKind::Declaration,
            None,
        );
    } else if briefing.get("resume") == Some(&Value::Null) {
        out.push_str("Resume: none found in the available briefing.\n");
    } else {
        out.push_str("Resume: field unavailable in the available briefing.\n");
    }

    out
}

fn render_close_run(value: &Value) -> String {
    let mut out = String::new();
    match boolean(value, "changed") {
        Some(true) => out.push_str("Durable run activity closed.\n"),
        Some(false) => out.push_str("Durable run activity was already closed.\n"),
        None => out.push_str("Run closure result unavailable.\n"),
    }
    for (key, label) in [
        ("activity_id", "Activity"),
        ("started_at", "Started at"),
        ("ended_at", "Ended at"),
    ] {
        if let Some(value) = string(value, key) {
            let _ = writeln!(out, "{label}: {}", display_inline(&value));
        }
    }
    out
}

fn render_management_result(label: &str, value: &Value) -> String {
    let mut out = format!("{label}\n");
    render_fields(&mut out, value, &["run_context"]);
    out
}

fn render_create_many(value: &Value) -> String {
    let ids = array(value, "ids");
    let created = ids.iter().filter(|id| id.is_string()).count();
    let mut out = format!("Created {created}/{} records\n", ids.len());
    for (index, id) in ids.iter().enumerate() {
        match id.as_str() {
            Some(id) => {
                let _ = writeln!(out, "- [{index}] {id}");
            }
            None => {
                let _ = writeln!(out, "- [{index}] not created");
            }
        }
    }
    let errors = array(value, "errors");
    if !errors.is_empty() {
        let _ = writeln!(out, "Errors: {}", errors.len());
        for error in errors {
            let index = integer(error, "index").unwrap_or(-1);
            let code = string(error, "code").unwrap_or_else(|| "unknown".into());
            let message = string(error, "message").unwrap_or_else(|| "no detail".into());
            let _ = writeln!(out, "- [{index}] {code}: {message}");
        }
    }
    let warnings = array(value, "warnings");
    if !warnings.is_empty() {
        let _ = writeln!(out, "Warnings: {} (see structured receipt)", warnings.len());
    }
    let body_digests = array(value, "body_digests");
    if !body_digests.is_empty() {
        let _ = writeln!(
            out,
            "Body digests: {} (see structured receipt)",
            body_digests.len()
        );
    }
    if !array(value, "results").is_empty() {
        let _ = writeln!(
            out,
            "Verbose created-record results are present in the structured receipt."
        );
    }
    out
}

fn render_resolve_many(value: &Value) -> String {
    let counts = value.get("counts").unwrap_or(&Value::Null);
    let resolved = integer(counts, "resolved").unwrap_or(0);
    let not_found = integer(counts, "not_found").unwrap_or(0);
    let ambiguous = integer(counts, "ambiguous").unwrap_or(0);
    let mut qualifiers = Vec::new();
    if let Some(record_type) = string(value, "type") {
        qualifiers.push(format!("type={record_type}"));
    }
    if let Some(kind) = string(value, "kind") {
        qualifiers.push(format!("kind={kind}"));
    }
    qualifiers.push(format!(
        "include_archived={}",
        boolean(value, "include_archived").unwrap_or(false)
    ));
    let mut out = format!(
        "Exact resolution: {resolved} resolved · {not_found} not found · {ambiguous} ambiguous ({})\n",
        qualifiers.join(", ")
    );
    for result in array(value, "results") {
        let index = integer(result, "index").unwrap_or(-1);
        let input = string(result, "input").unwrap_or_default();
        match string(result, "status").as_deref() {
            Some("resolved") => {
                let matched = result.get("match").unwrap_or(&Value::Null);
                let id = string(matched, "id").unwrap_or_else(|| "unknown".into());
                let name = string(matched, "name").unwrap_or_default();
                let record_type = string(matched, "type").unwrap_or_else(|| "unknown".into());
                let kind = string(matched, "kind").unwrap_or_else(|| "—".into());
                let _ = writeln!(
                    out,
                    "- [{index}] {input:?} → {id} · {name} · {record_type}/{kind}"
                );
            }
            Some("ambiguous") => {
                let matches = array(result, "matches");
                let _ = writeln!(
                    out,
                    "- [{index}] {input:?} → ambiguous ({} visible matches)",
                    integer(result, "match_count").unwrap_or(matches.len() as i64)
                );
                for matched in matches {
                    let id = string(matched, "id").unwrap_or_else(|| "unknown".into());
                    let name = string(matched, "name").unwrap_or_default();
                    let record_type = string(matched, "type").unwrap_or_else(|| "unknown".into());
                    let kind = string(matched, "kind").unwrap_or_else(|| "—".into());
                    let _ = writeln!(out, "  - {id} · {name} · {record_type}/{kind}");
                }
            }
            _ => {
                let _ = writeln!(out, "- [{index}] {input:?} → not found");
            }
        }
    }
    out
}

fn render_policy_state(value: &Value) -> String {
    let mode = string(value, "mode").unwrap_or_else(|| "unknown".into());
    match string(value, "anchor_id") {
        Some(anchor) => format!("{mode} (anchor {anchor})"),
        None => mode,
    }
}

fn render_manage_record_policy(value: &Value) -> String {
    if !array(value, "outcomes").is_empty() {
        let outcomes = array(value, "outcomes");
        let changed = outcomes
            .iter()
            .filter(|outcome| boolean(outcome, "changed") == Some(true))
            .count();
        let mut out = format!(
            "Record policy set: {changed}/{} items changed atomically\n",
            outcomes.len()
        );
        for outcome in outcomes {
            let index = integer(outcome, "index").unwrap_or(-1);
            let record_id = string(outcome, "record_id").unwrap_or_else(|| "unknown".into());
            let state = if boolean(outcome, "changed") == Some(true) {
                "changed"
            } else {
                "already converged"
            };
            let _ = writeln!(out, "- [{index}] {record_id}: {state}");
        }
        return out;
    }
    let mut out = match string(value, "record_id") {
        Some(record_id) => format!("Record policy for {record_id}\n"),
        None => "Record policy\n".into(),
    };

    if let Some(target) = string(value, "authorization_target_id") {
        let _ = writeln!(out, "Authorization target: {target}");
    }
    if value.get("mode").is_some() || value.get("anchor_id").is_some() {
        let _ = writeln!(out, "Policy: {}", render_policy_state(value));
    }
    if let Some(capability) = string(value, "caller_capability") {
        let _ = writeln!(out, "Caller capability: {capability}");
    }
    if let Some(authorized) = boolean(value, "policy_administration_authorized") {
        let _ = writeln!(
            out,
            "Policy administration: {}",
            if authorized {
                "authorized"
            } else {
                "not authorized"
            }
        );
    }

    if let Some(entries) = value.get("entries").and_then(Value::as_array) {
        let _ = writeln!(out, "Entries: {} (complete list)", entries.len());
        for entry in entries {
            let capability = string(entry, "capability").unwrap_or_else(|| "unknown".into());
            let subject = entry.get("subject").unwrap_or(&Value::Null);
            match string(subject, "kind").as_deref() {
                Some("members") => {
                    let _ = writeln!(out, "- members: {capability}");
                }
                Some("account") => {
                    let account = string(subject, "account_id").unwrap_or_else(|| "unknown".into());
                    let mut label = format!("account {account}");
                    if let Some(person) = subject.get("person").filter(|person| !person.is_null()) {
                        if let Some(person_id) = string(person, "record_id") {
                            let _ = write!(label, " -> person {person_id}");
                        }
                        if let Some(name) = string(person, "name") {
                            let _ = write!(label, " ({name})");
                        }
                    }
                    let _ = writeln!(out, "- {label}: {capability}");
                }
                _ => {
                    let _ = writeln!(out, "- {}: {capability}", inline_json(subject));
                }
            }
        }
    }

    if let Some(changed) = boolean(value, "changed") {
        let _ = writeln!(out, "Changed: {changed}");
    }
    if let Some(boundary_created) = boolean(value, "boundary_created") {
        let _ = writeln!(out, "Explicit boundary created: {boundary_created}");
    }
    if let Some(before) = value.get("before") {
        let _ = writeln!(out, "Before: {}", render_policy_state(before));
    }
    if let Some(after) = value.get("after") {
        let _ = writeln!(out, "After: {}", render_policy_state(after));
    }
    if let Some(event) = value.get("event") {
        let event_id = string(event, "id").unwrap_or_else(|| "unknown".into());
        match integer(event, "seq") {
            Some(seq) => {
                let _ = writeln!(out, "Policy event: {event_id} (seq {seq})");
            }
            None => {
                let _ = writeln!(out, "Policy event: {event_id}");
            }
        }
    }
    if let Some(revision) = string(value, "policy_revision") {
        let _ = writeln!(out, "Policy revision: {revision}");
    }
    out
}

fn citation_identity(value: &Value, key: &str) -> Option<String> {
    string(value, key).filter(|identity| {
        !identity.is_empty()
            && identity.chars().count() <= 512
            && !identity
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
    })
}

fn render_resolve_citation(value: &Value) -> String {
    const DETAIL_BUDGET: usize = 24_000;
    const COMPONENT_CAP: usize = 8_000;

    let Some(_) = value.as_object() else {
        return format!(
            "Citation resolution payload is malformed and was not interpreted; {READ_JSON_RECOVERY}\n"
        );
    };

    let mut out = match (
        citation_identity(value, "annotation_id"),
        citation_identity(value, "target_record_id"),
    ) {
        (Some(id), Some(source)) => format!(
            "Citation {}\nSource: {}\n",
            display_inline(&id),
            display_inline(&source)
        ),
        _ => format!(
            "Citation resolution identifiers are missing or malformed; no source identity was inferred. {READ_JSON_RECOVERY}\n"
        ),
    };
    let mut remaining = DETAIL_BUDGET;

    for (label, key, valid) in [
        (
            "Validation: ",
            "validation",
            value.get("validation").is_some_and(Value::is_object),
        ),
        (
            "Anchored source: ",
            "anchored",
            value.get("anchored").is_some_and(Value::is_object),
        ),
        (
            "Current source: ",
            "current",
            value
                .get("current")
                .is_some_and(|current| current.is_object() || current.is_null()),
        ),
        (
            "Selectors: ",
            "selectors",
            value.get("selectors").is_some_and(Value::is_array),
        ),
    ] {
        if valid {
            render_bounded_context_component(
                &mut out,
                label,
                &value[key],
                &mut remaining,
                COMPONENT_CAP,
            );
        } else {
            let _ = writeln!(
                out,
                "{}missing or malformed; no value was inferred. {READ_JSON_RECOVERY}",
                label.trim_end()
            );
        }
    }

    match boolean(value, "read_only") {
        Some(read_only) => {
            let _ = writeln!(out, "Read only: {read_only}");
        }
        None => {
            let _ = writeln!(
                out,
                "Read-only marker: missing or malformed; no mutation semantics were inferred. {READ_JSON_RECOVERY}"
            );
        }
    }
    render_context_unknowns(
        &mut out,
        "citation-resolution",
        value,
        |key| {
            matches!(
                key,
                "annotation_id"
                    | "target_record_id"
                    | "anchored"
                    | "current"
                    | "validation"
                    | "selectors"
                    | "read_only"
                    | "run_context"
            )
        },
        &mut remaining,
    );
    if remaining == 0 {
        let _ = writeln!(
            out,
            "Citation-resolution text budget reached its limit; {READ_JSON_RECOVERY}"
        );
    }
    out
}

fn render_manage_citations(value: &Value) -> String {
    const WRITE_RECOVERY: &str = "Exact response remains in structuredContent; do not repeat a possibly non-idempotent write solely to obtain another format. For a future write, request format:\"json\" on the original call.";

    let Some(_) = value.as_object() else {
        return format!(
            "Citation write payload is malformed and no outcome was inferred; {WRITE_RECOVERY}\n"
        );
    };
    let citation_id = citation_identity(value, "citation_id");
    let action = string(value, "action");
    let event_seq = integer(value, "event_seq").filter(|seq| *seq > 0);
    let reason = string(value, "reason").filter(|reason| !reason.trim().is_empty());
    let receipt_valid = citation_id.is_some()
        && matches!(action.as_deref(), Some("reanchored" | "removed"))
        && event_seq.is_some()
        && reason.is_some();
    let mut out = match (receipt_valid, citation_id.as_deref(), action.as_deref()) {
        (true, Some(id), Some(action @ ("reanchored" | "removed"))) => {
            format!("Citation {} {action}.\n", display_inline(id))
        }
        _ => format!(
            "Citation write receipt is incomplete, malformed, or unsupported; no outcome was inferred. {WRITE_RECOVERY}\n"
        ),
    };
    match event_seq {
        Some(seq) => {
            let _ = writeln!(out, "Event sequence: {seq}");
        }
        _ => {
            let _ = writeln!(
                out,
                "Event sequence: missing or malformed; the durable write position was not inferred. {WRITE_RECOVERY}"
            );
        }
    }
    match reason {
        Some(reason) => {
            let encoded = inline_json(&json!(reason));
            let (preview, shortened) = one_line_preview(&encoded, 2_000);
            let _ = writeln!(
                out,
                "Reason: {preview}{}",
                if shortened {
                    format!(" (shortened; {WRITE_RECOVERY})")
                } else {
                    String::new()
                }
            );
        }
        None => {
            let _ = writeln!(
                out,
                "Reason: missing or malformed; no reason was inferred. {WRITE_RECOVERY}"
            );
        }
    }
    let unknown = unknown_object_keys(value, |key| {
        matches!(
            key,
            "citation_id" | "action" | "event_seq" | "reason" | "run_context"
        )
    });
    if !unknown.is_empty() {
        let encoded = inline_json(&json!(unknown));
        let (preview, shortened) = one_line_preview(&encoded, 1_000);
        let _ = writeln!(
            out,
            "Additional citation-write fields omitted from text: {preview}{}; {WRITE_RECOVERY}",
            if shortened {
                " (field-name list shortened)"
            } else {
                ""
            }
        );
    }
    out
}

const ATTRIBUTION_TEXT_BUDGET: usize = 24_000;
const ATTRIBUTION_COMPONENT_CAP: usize = 8_000;
const ATTRIBUTION_WRITE_RECOVERY: &str = "Exact response remains in structuredContent; do not repeat a possibly non-idempotent write solely to obtain another format. For a future write, request format:\"json\" on the original call.";

fn attribution_identity(value: &Value, key: &str) -> Option<String> {
    citation_identity(value, key)
}

fn render_attribution_write_unknowns(
    out: &mut String,
    value: &Value,
    known: impl Fn(&str) -> bool,
) {
    let unknown = unknown_object_keys(value, known);
    if unknown.is_empty() {
        return;
    }
    let encoded = inline_json(&json!(unknown));
    let (preview, shortened) = one_line_preview(&encoded, 1_000);
    let _ = writeln!(
        out,
        "Additional attribution-write fields omitted from text: {preview}{}; {ATTRIBUTION_WRITE_RECOVERY}",
        if shortened {
            " (field-name list shortened)"
        } else {
            ""
        }
    );
}

fn render_create_attribution(value: &Value) -> String {
    let Some(_) = value.as_object() else {
        return format!(
            "Attribution-create payload is malformed and no outcome was inferred; {ATTRIBUTION_WRITE_RECOVERY}\n"
        );
    };
    let annotation = attribution_identity(value, "annotation_id");
    let bearer = attribution_identity(value, "bearer_id");
    let mode = string(value, "claim_mode")
        .filter(|mode| matches!(mode.as_str(), "declaration" | "assessment"));
    let attestation = attribution_identity(value, "action_attestation_id");
    let complete =
        annotation.is_some() && bearer.is_some() && mode.is_some() && attestation.is_some();
    let mut out = match (
        complete,
        annotation.as_deref(),
        bearer.as_deref(),
        mode.as_deref(),
    ) {
        (true, Some(annotation), Some(bearer), Some(mode)) => format!(
            "Attribution {} created for {} as {mode}.\n",
            display_inline(annotation),
            display_inline(bearer)
        ),
        _ => format!(
            "Attribution-create receipt is incomplete, malformed, or unsupported; no outcome was inferred. {ATTRIBUTION_WRITE_RECOVERY}\n"
        ),
    };
    match attestation {
        Some(attestation) => {
            let _ = writeln!(out, "Action attestation: {}", display_inline(&attestation));
        }
        None => {
            let _ = writeln!(
                out,
                "Action attestation: missing or malformed; durable action identity was not inferred. {ATTRIBUTION_WRITE_RECOVERY}"
            );
        }
    }
    render_attribution_write_unknowns(&mut out, value, |key| {
        matches!(
            key,
            "annotation_id" | "bearer_id" | "claim_mode" | "action_attestation_id" | "run_context"
        )
    });
    out
}

fn render_read_attributions(value: &Value) -> String {
    let Some(_) = value.as_object() else {
        return format!(
            "Attribution-read payload is malformed and was not interpreted; {READ_JSON_RECOVERY}\n"
        );
    };
    let bearer = attribution_identity(value, "bearer_id");
    let total = integer(value, "attribution_count").filter(|count| *count >= 0);
    let rows = value.get("attributions").and_then(Value::as_array);
    let limit = integer(value, "limit").filter(|limit| *limit > 0);
    let offset = integer(value, "offset").filter(|offset| *offset >= 0);
    let mut out = match (bearer.as_deref(), total, rows, offset) {
        (Some(bearer), Some(total), Some(rows), Some(offset)) => format!(
            "Attributions for {}: {total} caller-visible claim(s); {} returned from offset {offset}.\n",
            display_inline(bearer),
            rows.len()
        ),
        _ => format!(
            "Attribution-read identity, count, page, or offset is missing or malformed; no complete page claim was inferred. {READ_JSON_RECOVERY}\n"
        ),
    };
    match limit {
        Some(limit) => {
            let _ = writeln!(out, "Page limit: {limit}");
        }
        None => {
            let _ = writeln!(
                out,
                "Page limit: missing or malformed; page bounds were not inferred. {READ_JSON_RECOVERY}"
            );
        }
    }
    match value.get("as_of_event_seq") {
        Some(Value::Null) => out.push_str("Temporal scope: live current attribution state.\n"),
        Some(as_of) if as_of.as_i64().is_some_and(|seq| seq > 0) => {
            let _ = writeln!(
                out,
                "Temporal scope: attribution history as of event sequence {} (receiver-local authority and evidence invalidation remain current).",
                as_of.as_i64().unwrap_or_default()
            );
        }
        _ => {
            let _ = writeln!(
                out,
                "Temporal scope: missing or malformed; live versus historical scope was not inferred. {READ_JSON_RECOVERY}"
            );
        }
    }

    let mut remaining = ATTRIBUTION_TEXT_BUDGET;
    match rows {
        Some(rows) => {
            for (index, attribution) in rows.iter().enumerate() {
                if !render_bounded_context_component(
                    &mut out,
                    &format!("Attribution row {}: ", index + 1),
                    attribution,
                    &mut remaining,
                    ATTRIBUTION_COMPONENT_CAP,
                ) {
                    let omitted = rows.len() - index;
                    let _ = writeln!(
                        out,
                        "Attribution detail budget exhausted; {omitted} returned row(s) omitted from text. {READ_JSON_RECOVERY}"
                    );
                    break;
                }
            }
            if let (Some(total), Some(offset)) = (total, offset) {
                let returned = rows.len() as i64;
                if offset.saturating_add(returned) < total {
                    out.push_str("More caller-visible attributions remain after this page.\n");
                } else if offset.saturating_add(returned) == total {
                    out.push_str(
                        "This attribution page reaches the reported caller-visible total.\n",
                    );
                } else {
                    let _ = writeln!(
                        out,
                        "Returned page conflicts with the reported total; exhaustion was not inferred. {READ_JSON_RECOVERY}"
                    );
                }
            }
        }
        None => {
            let _ = writeln!(
                out,
                "Attribution rows: missing or malformed; no empty-set conclusion was inferred. {READ_JSON_RECOVERY}"
            );
        }
    }

    match value.get("interpretation") {
        Some(interpretation) if interpretation.is_object() => {
            if !render_bounded_context_component(
                &mut out,
                "Interpretation projection: ",
                interpretation,
                &mut remaining,
                ATTRIBUTION_COMPONENT_CAP,
            ) {
                let _ = writeln!(
                    out,
                    "Interpretation projection omitted after the shared text budget was exhausted. {READ_JSON_RECOVERY}"
                );
            }
        }
        _ => {
            let _ = writeln!(
                out,
                "Interpretation projection: missing or malformed; no interpreted stance was inferred. {READ_JSON_RECOVERY}"
            );
        }
    }
    match value.get("explanation") {
        Some(Value::Null) => out.push_str("Claim-specific explanation: none returned.\n"),
        Some(explanation) if explanation.is_object() => {
            if !render_bounded_context_component(
                &mut out,
                "Claim-specific explanation: ",
                explanation,
                &mut remaining,
                ATTRIBUTION_COMPONENT_CAP,
            ) {
                let _ = writeln!(
                    out,
                    "Claim-specific explanation omitted after the shared text budget was exhausted. {READ_JSON_RECOVERY}"
                );
            }
        }
        _ => {
            let _ = writeln!(
                out,
                "Claim-specific explanation: missing or malformed; absence was not inferred. {READ_JSON_RECOVERY}"
            );
        }
    }
    render_context_unknowns(
        &mut out,
        "attribution-read",
        value,
        |key| {
            matches!(
                key,
                "bearer_id"
                    | "attribution_count"
                    | "attributions"
                    | "interpretation"
                    | "explanation"
                    | "limit"
                    | "offset"
                    | "as_of_event_seq"
                    | "run_context"
            )
        },
        &mut remaining,
    );
    if remaining == 0 {
        let _ = writeln!(
            out,
            "Attribution-read text budget reached its limit; {READ_JSON_RECOVERY}"
        );
    }
    out
}

fn render_manage_attributions(value: &Value) -> String {
    let Some(_) = value.as_object() else {
        return format!(
            "Attribution-management payload is malformed and no outcome was inferred; {ATTRIBUTION_WRITE_RECOVERY}\n"
        );
    };
    let annotation = attribution_identity(value, "annotation_id");
    let action = string(value, "action")
        .filter(|action| matches!(action.as_str(), "retracted" | "evidence_added"));
    let mut out = match (annotation.as_deref(), action.as_deref()) {
        (Some(annotation), Some(action)) => format!(
            "Attribution {} {action}.\n",
            display_inline(annotation)
        ),
        _ => format!(
            "Attribution-management receipt is incomplete, malformed, or unsupported; no outcome was inferred. {ATTRIBUTION_WRITE_RECOVERY}\n"
        ),
    };
    render_attribution_write_unknowns(&mut out, value, |key| {
        matches!(key, "annotation_id" | "action" | "run_context")
    });
    out
}

fn render_interpretation_summary(out: &mut String, projection: &Value, indent: &str) {
    let status = string(projection, "status").unwrap_or_else(|| "unavailable".into());
    let count = integer(projection, "attribution_count")
        .map(|count| count.to_string())
        .unwrap_or_else(|| "unavailable".into());
    let _ = writeln!(
        out,
        "{indent}Interpretation: {status} · caller-visible claims {count}"
    );
    for group in array(projection, "groups") {
        let headline = string(group, "headline")
            .unwrap_or_else(|| "Interpretation details are unavailable.".into());
        let target = group
            .pointer("/target/state")
            .and_then(Value::as_str)
            .unwrap_or("unavailable");
        let _ = writeln!(out, "{indent}  - {headline} [target {target}]");
    }
    if boolean(projection, "complete") == Some(false) {
        let _ = writeln!(
            out,
            "{indent}  Projection incomplete; unavailable or withheld details are not absent."
        );
    }
    let _ = writeln!(
        out,
        "{indent}  Delegation, confidence, and counts do not establish endorsement, truth, or consensus."
    );
}

fn render_manage_instructions(value: &Value) -> String {
    let Some(object) = value.as_object() else {
        return format!(
            "Instruction-management response is malformed; no outcome was inferred.\nExact response: {}\n",
            inline_json(value)
        );
    };

    // Handler responses do not carry the requested action, so discriminate on
    // shapes that are unique across the current union and do not invent a more
    // specific mutation than the receipt establishes. In particular, an empty
    // list and compare_seeded_default are reads, never an implicit update.
    let heading = if object.get("bindings").is_some_and(Value::is_array) {
        format!(
            "Instruction binding list (read-only): {} returned.\n",
            array(value, "bindings").len()
        )
    } else if object.contains_key("current_digest")
        && object.contains_key("shipped_template_available")
    {
        "Seeded instruction source comparison (read-only).\n".into()
    } else if object.contains_key("source_record_id")
        && object.contains_key("template_key")
        && object.contains_key("body_digest")
    {
        "Seeded instruction source result.\n".into()
    } else if object.contains_key("binding_id") {
        "Instruction binding result.\n".into()
    } else {
        format!(
            "Instruction-management response has an unsupported shape; no outcome was inferred.\nExact response: {}\n",
            inline_json(value)
        )
    };
    if heading.contains("unsupported shape") {
        return heading;
    }
    let mut out = heading;
    render_fields(&mut out, value, &["run_context"]);
    out
}

fn render_manage_onboarding(value: &Value) -> String {
    let Some(object) = value.as_object() else {
        return format!(
            "Onboarding-management response is malformed; no outcome was inferred.\nExact response: {}\n",
            inline_json(value)
        );
    };

    let heading = if object.get("programmes").is_some_and(Value::is_array) {
        format!(
            "Onboarding programme list (read-only): {} returned.\n",
            array(value, "programmes").len()
        )
    } else if object.contains_key("audience_digest")
        && object.contains_key("account_ids")
        && object.contains_key("next_generation")
    {
        if object.contains_key("changed") {
            "Onboarding generation result.\n".into()
        } else {
            "Onboarding generation preview (read-only).\n".into()
        }
    } else if object.contains_key("programme_id") && object.contains_key("state") {
        "Onboarding obligation result.\n".into()
    } else if object.contains_key("programme_id") && object.contains_key("source_record_id") {
        "Onboarding programme source result.\n".into()
    } else if object.contains_key("programme_id") {
        "Onboarding programme result.\n".into()
    } else {
        format!(
            "Onboarding-management response has an unsupported shape; no outcome was inferred.\nExact response: {}\n",
            inline_json(value)
        )
    };
    if heading.contains("unsupported shape") {
        return heading;
    }
    let mut out = heading;
    render_fields(&mut out, value, &["run_context"]);
    out
}

fn render_record_version_diff(value: &Value) -> String {
    let id = value
        .get("record_id")
        .and_then(Value::as_str)
        .unwrap_or("record");
    // Absent endpoints must not collapse into `revision 0 → 0`: that is an
    // impossible transition presented as one that happened.
    let before = claimed_integer(value.pointer("/before/as_of_seq"), "before");
    let after = claimed_integer(value.pointer("/after/as_of_seq"), "after");
    let name = value
        .pointer("/after/record/name")
        .and_then(Value::as_str)
        .unwrap_or(id);
    format!("Version diff for {name} ({id}): revision {before} → {after}. Open the App for the before/after body and intervening events.\n")
}

fn render_suggestion_review(value: &Value) -> String {
    let id = value
        .pointer("/target/id")
        .and_then(Value::as_str)
        .unwrap_or("record");
    let name = value
        .pointer("/target/name")
        .and_then(Value::as_str)
        .unwrap_or(id);
    // A missing count is not "none outstanding". Saying "0 open suggestion(s)"
    // when the payload carried no count invites an agent to skip a review that
    // is in fact outstanding, so the absent case says so instead — in the one
    // vocabulary `claimed_integer` defines, so that changing how absence reads
    // changes it everywhere at once.
    let counted = claimed_integer(value.get("suggestion_count"), "suggestion_count");
    format!("Suggestion review for {name} ({id}): {counted} open suggestion(s). Open the App to stage a selection, preflight it, and commit once.\n")
}

/// Model-visible footer shared by successful text renderings and tool errors.
/// The model-facing text must carry the echo explicitly because run context is
/// part of the standalone default-text result. Only explicit JSON/App framing
/// or a defensive renderer fallback duplicates it in `structuredContent`.
pub fn render_run_context(context: &Value) -> String {
    let run_key = display_inline(
        context
            .get("run_key")
            .and_then(Value::as_str)
            .unwrap_or("(none)"),
    );
    let raw_intent = context
        .get("intent")
        .and_then(Value::as_str)
        .unwrap_or("(none)");
    let (intent, intent_shortened) = one_line_preview(raw_intent, 500);
    let intent = display_inline(&intent);
    let mut out = format!("\nRun context: {run_key} · intent: {intent}");
    if let Some(parent) = context.get("parent_key").and_then(Value::as_str) {
        let _ = write!(out, " · parent: {}", display_inline(parent));
    }
    out.push('\n');
    if intent_shortened {
        out.push_str("Run context intent shortened in text.\n");
    }
    if let Some(follow_url) = context.get("follow_url").and_then(Value::as_str) {
        let _ = writeln!(out, "Follow this run: {}", display_inline(follow_url));
    }
    for note in array(context, "notes").iter().filter_map(Value::as_str) {
        let (note, shortened) = one_line_preview(note, 500);
        let _ = writeln!(out, "Run note: {}", display_inline(&note));
        if shortened {
            out.push_str("Run note shortened in text.\n");
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Payload accessors
//
// Every renderer reads through these rather than indexing directly: a payload
// that drifts should cost a line of the rendering, not the whole call.
// ---------------------------------------------------------------------------

fn string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn display_inline(text: &str) -> String {
    let mut displayed = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_control() {
            displayed.extend(character.escape_default());
        } else {
            displayed.push(character);
        }
    }
    displayed
}

/// Natural-language projection of the structured lifecycle envelope. This is
/// deliberately a renderer concern: machine-readable responses retain the
/// complete discriminated object while prose stays compact and honest.
fn lifecycle_display(value: &Value) -> Option<String> {
    let interpretation = value.get("lifecycle_interpretation")?;
    match interpretation.get("status")?.as_str()? {
        "governed" => interpretation
            .pointer("/value/canonical")
            .and_then(Value::as_str)
            .map(str::to_string),
        "unclassified" => {
            let raw = interpretation.get("raw")?.as_str()?;
            let reason = interpretation
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            Some(format!("{raw} (unclassified: {reason})"))
        }
        "absent" => None,
        _ => None,
    }
}

fn integer(value: &Value, key: &str) -> Option<i64> {
    value.get(key).and_then(Value::as_i64)
}

fn boolean(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

/// Render a field that the surrounding sentence makes a claim about.
///
/// `unwrap_or_default()` must not be used for these: it turns an absent count
/// into `0` and an absent category into a plausible word, and the sentence
/// then asserts it as fact. "0 open suggestion(s)" reads as "checked, and
/// clear"; `revision 0 → 0` reads as a transition that happened. Absent and
/// malformed values render as themselves here, so a genuine zero and a missing
/// count cannot be confused. The guard in `tests/records/render.rs` keeps new
/// renderers off the default.
fn claimed_integer(field: Option<&Value>, label: &str) -> String {
    match field {
        None | Some(Value::Null) => format!("({label} not reported)"),
        Some(found) => match found.as_i64() {
            Some(number) => number.to_string(),
            None => format!("({label} unreadable: {})", inline_json(found)),
        },
    }
}

/// The categorical counterpart of [`claimed_integer`]. An absent field and a
/// producer that explicitly asserted `unknown` are different claims, so the
/// absent case never borrows a word the payload could itself have carried.
fn claimed_string(field: Option<&Value>, label: &str) -> String {
    match field {
        None | Some(Value::Null) => format!("({label} not reported)"),
        Some(Value::String(text)) => display_inline(text),
        Some(found) => format!("({label} unreadable: {})", inline_json(found)),
    }
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
}

/// A complete, single-line representation of an arbitrary JSON value.
///
/// Renderers use this for open-ended payload fragments (event payloads, SQL
/// cells and schema shapes). Unlike a prose summary it cannot silently discard
/// a field the renderer does not know yet.
fn inline_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<unserializable JSON>".into())
}

fn temporal_header(value: &Value) -> String {
    let Some(resolved) = integer(value, "resolved_content_seq") else {
        return String::new();
    };
    let head = integer(value, "content_head_seq").unwrap_or(resolved);
    let selector = value
        .get("as_of")
        .map(inline_json)
        .unwrap_or_else(|| "{}".into());
    let observed_at = string(value, "observed_at")
        .map(|observed| format!(", observed at {observed}"))
        .unwrap_or_default();
    let local_database = string(value, "local_database_id")
        .map(|id| format!("local database {} · ", display_inline(&id)))
        .unwrap_or_default();
    format!(
        "{local_database}as_of {selector} — resolved content seq {resolved}, observed head {head}{observed_at}\n"
    )
}

/// Human-readable scalar, JSON for containers. Strings stay unquoted where a
/// labelled line already supplies the boundary.
fn display_value(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Null => "null".into(),
        other => inline_json(other),
    }
}

/// Emit every field of an object except fields rendered specially by a caller.
fn render_fields(out: &mut String, value: &Value, skip: &[&str]) {
    let Some(object) = value.as_object() else {
        let _ = writeln!(out, "{}", inline_json(value));
        return;
    };
    for (key, value) in object {
        if skip.contains(&key.as_str()) {
            continue;
        }
        let _ = writeln!(out, "{key}: {}", display_value(value));
    }
}

/// A record's display label: `type/kind` when a kind narrows the type.
fn type_label(value: &Value) -> String {
    let record_type = display_inline(&string(value, "type").unwrap_or_default());
    match string(value, "kind") {
        Some(kind) if !kind.is_empty() => format!("{record_type}/{}", display_inline(&kind)),
        _ => record_type,
    }
}

/// `"a, b, c"` from an array of strings.
fn join_strings(values: &[Value]) -> String {
    values
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Collapse whitespace and cap a free-text field — bodies and snippets are
/// unbounded and would otherwise dominate a rendering meant to be scanned.
fn one_line(text: &str, max: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        return flat;
    }
    let kept: String = flat.chars().take(max).collect();
    format!("{}…", kept.trim_end())
}

/// Render a one-line preview and report whether it changed the source.
///
/// Whitespace folding is deliberately counted as an omission too: callers
/// that need canonical Markdown/code formatting must be told where to recover
/// it even when the character cap itself was not reached.
fn one_line_preview(text: &str, max: usize) -> (String, bool) {
    let preview = one_line(text, max);
    let changed = preview != text;
    (preview, changed)
}

/// Left-pad a column to `width`, never truncating: a clipped id is a broken
/// id, and every id in a rendering is one the agent may need to call back with.
fn pad(text: &str, width: usize) -> String {
    let len = text.chars().count();
    if len >= width {
        return text.to_string();
    }
    format!("{text}{}", " ".repeat(width - len))
}

/// The widest value of a column, for aligning a block of rows.
fn column_width(rows: &[Value], of: impl Fn(&Value) -> String) -> usize {
    rows.iter()
        .map(|row| of(row).chars().count())
        .max()
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// bootstrap
// ---------------------------------------------------------------------------

fn is_engine_instruction(entry: &Value) -> bool {
    entry.get("scope").and_then(Value::as_str) == Some("engine")
        && entry.pointer("/source/type").and_then(Value::as_str) == Some("engine")
}

fn bootstrap_engine_orientation(value: &Value) -> Option<&str> {
    array(value, "entries")
        .iter()
        .find(|entry| is_engine_instruction(entry))
        .and_then(|entry| entry.get("content"))
        .and_then(Value::as_str)
}

fn relevant_first_use_obligation(obligation: &Value) -> bool {
    matches!(
        obligation.get("programme_id").and_then(Value::as_str),
        Some("native:onboarding-owner-first-run" | "native:onboarding-member-joined")
    )
}

fn render_bootstrap_repair(out: &mut String, instructions: &Value, obligations: &[&Value]) {
    let invalid_instructions = string(instructions, "status").as_deref() != Some("ready");
    if invalid_instructions {
        out.push_str("## Action required before relying on standing context\n\n");
        out.push_str("Native could not establish one valid, complete standing-guidance stack, so it withheld partial guidance. Repair or remove the invalid binding before continuing work that depends on it.\n\n");
        for diagnostic in array(instructions, "diagnostics") {
            let code = string(diagnostic, "code").unwrap_or_else(|| "invalid".into());
            let message = string(diagnostic, "message").unwrap_or_default();
            match string(diagnostic, "source_record_id") {
                Some(source) => {
                    let _ = writeln!(out, "- `{code}` · source `{source}` · {message}");
                }
                None => {
                    let _ = writeln!(out, "- `{code}` · {message}");
                }
            }
        }
        out.push_str("\nInspect the caller-visible bindings with `manage_instructions` using `{\"action\":\"list\"}`.\n");
    } else {
        out.push_str("## Action required before first-use onboarding continues\n");
    }
    if obligations.len() > 1 {
        out.push_str("\nMore than one relevant first-use journey is pending, so Native will not silently choose one:\n\n");
        for obligation in obligations {
            let programme = string(obligation, "programme_id").unwrap_or_else(|| "unknown".into());
            let generation = integer(obligation, "generation").unwrap_or_default();
            let _ = writeln!(out, "- programme `{programme}`, generation {generation}");
        }
        out.push_str("\nAsk a workspace owner to inspect the programme state with `manage_onboarding` using `{\"action\":\"list_programmes\"}`, then repair or resolve the duplicate before onboarding continues.\n");
    }
}

fn render_bootstrap_guidance(out: &mut String, instructions: &Value) {
    out.push_str("## Standing guidance\n\nStanding instructions resolved successfully. Apply all active instruction bodies below together. Their scopes describe provenance, not an automatic priority. If active instructions materially conflict, exercise judgement and ask the person only when necessary.\n");
    let entries = array(instructions, "entries")
        .iter()
        .filter(|entry| !is_engine_instruction(entry))
        .collect::<Vec<_>>();
    if entries.is_empty() {
        out.push_str("\nNo additional standing instruction body is active.\n");
    }
    for entry in entries {
        let scope = string(entry, "scope").unwrap_or_else(|| "portable".into());
        let kind = string(entry, "kind").unwrap_or_else(|| "standing".into());
        let source = entry.get("source").unwrap_or(&Value::Null);
        if source.get("type").and_then(Value::as_str) == Some("record") {
            let id = string(source, "record_id").unwrap_or_else(|| "unknown".into());
            let title = string(source, "title").unwrap_or_else(|| id.clone());
            let _ = writeln!(out, "\n### {title}\n\nSource: `{id}` · {scope}/{kind}\n");
        } else {
            let _ = writeln!(out, "\n### Portable instruction\n\nScope: {scope}/{kind}\n");
        }
        out.push_str("--- exact instruction body ---\n");
        let body = entry.get("content").and_then(Value::as_str).unwrap_or("");
        out.push_str(body);
        if !body.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("--- end instruction body ---\n");
    }
}

fn render_first_use_onboarding(out: &mut String, obligation: &Value) {
    let phase = obligation.get("progress_phase").and_then(Value::as_str);
    match phase {
        None => out.push_str(
            "## First-use onboarding\n\nOffer three useful ways to begin:\n\n1. **Set up a practical workflow** — use one small piece of real work and get something useful working in this conversation.\n2. **Compare Native with another tool** — relate Native to something the person already uses, such as Notion, Linear, or plain files.\n3. **Explain Native conceptually** — give the person the mental model: what Native keeps, how agents use it, and what remains under their control.\n\nRecommend the practical workflow. It gives the person something concrete to evaluate, demonstrates the core loop of recording and recovering useful work, and makes later comparison or explanation more grounded.\n\nAdapt the wording to the conversation. If the person has already expressed a clear preference, follow it without asking them to choose again. Ask questions one at a time and only when the answer materially changes the next useful action.\n\nA practical workflow should normally produce or improve a useful workspace record. Explain that expectation when presenting the route. Comparison and conceptual explanation do not require an artifact to be useful or complete. Existing artifact-preview and consent gates remain authoritative.\n\nDo not treat opening a session, showing a preview, interruption, silence, or declining one proposed write as completion or decline. Record route selection using only its stable route ID; record value delivered only after the person confirms it was useful; resolve completion or decline only when the person establishes that terminal state.\n",
        ),
        Some("deferred") => out.push_str(
            "## First-use onboarding\n\nThis journey is explicitly deferred. A resume-after time is reminder eligibility only; it does not resume the journey or authorize prompting or writing. Wait for explicit confirmation before resuming, and do not replay the three-route menu.\n",
        ),
        Some(progress) => {
            out.push_str("## First-use onboarding\n\nContinue from the recorded progress without replaying the three-route menu or repeating completed steps. A recorded route may be followed directly; Bootstrap does not infer an unrecorded conversational preference.\n");
            if let Some(route) = string(obligation, "selected_route_id") {
                let _ = writeln!(out, "\nContinue the selected stable route `{route}` unless the person explicitly changes direction.");
            }
            match progress {
                "artifact_previewed"
                    if string(obligation, "progress_run_relation").as_deref()
                        == Some("current_run") => out.push_str("\nThe exact artifact preview has consent in this run. Preserve the existing preview/write gate: write exactly that draft, then record `artifact_written`.\n"),
                "artifact_previewed" => out.push_str("\nThe earlier artifact preview belongs to another or unknown run. Re-show the exact draft and obtain fresh explicit consent before writing.\n"),
                "artifact_written" => out.push_str("\nThe consented artifact has already been recorded. Do not preview or write it again; continue toward confirmed value or an explicit terminal outcome.\n"),
                "value_delivered" => out.push_str("\nValue has been recorded as user-confirmed. Do not silently mark onboarding complete or declined; wait for the person to establish that terminal outcome.\n"),
                _ => {}
            }
        }
    }
}

fn yaml_scalar(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".into())
}

/// Which footing facts the prose "Current footing" section actually stated
/// earlier in this response. Each field is set by the block that writes it, so
/// a payload that omits the input for that block leaves the field `false` and
/// the YAML states the fact instead. It must never be passed as a literal:
/// `true` where the prose block did not run means the fact is stated nowhere.
#[derive(Clone, Copy, Default)]
struct FootingStated {
    /// The workspace block, which names `native:root` and `native:unfiled`.
    destinations: bool,
    /// The private-agent-context line, which also says when to use it.
    private_context: bool,
}

/// `footing` reports which parts of the prose "Current footing" section ran
/// earlier in this response. What it stated — in a form that also says when the
/// private context should be used — this block does not repeat. What it did not
/// state (the repair path returns before that section, and a payload without a
/// workspace skips the destinations block) is stated here instead: once, either
/// way, never nowhere.
///
/// `next_steps_stated` reports whether callable next-step items were actually
/// emitted. Pointing at steps that do not exist is itself a false claim, so the
/// pointer is only written when there is something to point at.
fn render_internal_continuation(
    out: &mut String,
    value: &Value,
    obligation: Option<&Value>,
    footing: FootingStated,
    next_steps_stated: bool,
) {
    let Some(run_key) = value
        .get("session")
        .or_else(|| value.get("run"))
        .and_then(|run| run.get("run_key"))
        .and_then(Value::as_str)
    else {
        return;
    };
    out.push_str("\n## Internal continuation state — use silently; do not narrate\n");
    if next_steps_stated {
        out.push_str("\nCallable next steps are stated once, under \"Available next steps\" above; they are not repeated here.\n");
    }
    out.push_str("\n```yaml\nrun:\n");
    let _ = writeln!(out, "  run_key: &run_key {}", yaml_scalar(run_key));
    out.push_str("  whole_run_rollback: false\n");
    let private = value
        .pointer("/principal/private_context/root_record_id")
        .and_then(Value::as_str)
        .filter(|_| !footing.private_context);
    if !footing.destinations || private.is_some() {
        out.push_str("\ndestinations:\n");
        if !footing.destinations {
            out.push_str(
                "  workspace_root: \"native:root\"\n  workspace_default: \"native:unfiled\"\n",
            );
        }
        if let Some(private) = private {
            let _ = writeln!(out, "  private_agent_context: {}", yaml_scalar(private));
        }
    }
    if let Some(obligation) = obligation {
        out.push_str("\nonboarding:\n  state: pending\n");
        for (key, field) in [
            ("programme_id", "programme_id"),
            ("progress_state", "progress_state"),
            ("progress_phase", "progress_phase"),
            ("selected_route", "selected_route_id"),
            ("resume_after", "resume_after"),
            ("artifact_reference", "progress_artifact_id"),
        ] {
            if let Some(field_value) = obligation.get(field).and_then(Value::as_str) {
                let _ = writeln!(out, "  {key}: {}", yaml_scalar(field_value));
            }
        }
        if let Some(generation) = integer(obligation, "generation") {
            let _ = writeln!(out, "  generation: {generation}");
        }
    }
    // `set_intent` and `get_structure` used to be restated here as YAML
    // continuations. The prose is the richer statement — it covers every
    // affordance, not just these two, and says why each one is worth calling —
    // so it is the one that survives. `get_structure` is always among the
    // "Available next steps" items, arguments included. `set_intent` is not:
    // `next_steps()` emits it only while the intent is undeclared (see
    // `orientation.rs`), which is exactly when a caller needs it; once it is
    // declared, the "Intentful sessions" prose above still names the tool and
    // says when to call it again. So neither tool loses its statement, but the
    // two are not stated in the same place.
    //
    // The onboarding continuations below have no prose counterpart carrying
    // their argument shapes, so they stay.
    if let Some(obligation) = obligation
        .filter(|item| item.get("progress_phase").and_then(Value::as_str) != Some("deferred"))
    {
        out.push_str("\ncontinuations:\n");
        let programme = obligation
            .get("programme_id")
            .and_then(Value::as_str)
            .unwrap_or("<programme_id>");
        let generation = integer(obligation, "generation").unwrap_or_default();
        if obligation
            .get("selected_route_id")
            .and_then(Value::as_str)
            .is_none()
        {
            let _ = writeln!(out, "  record_route_selected:\n    tool: manage_onboarding\n    arguments:\n      action: record_progress\n      programme_id: {}\n      generation: {generation}\n      phase: route_selected\n      evidence.route_id: <practical_workflow | comparative_evaluation | conceptual_explanation>\n      idempotency_key: <stable key>\n      reason: <why this route was selected>\n      run_key: *run_key", yaml_scalar(programme));
        }
        let _ = writeln!(out, "  record_value_delivered:\n    tool: manage_onboarding\n    arguments:\n      action: record_progress\n      programme_id: {}\n      generation: {generation}\n      phase: value_delivered\n      evidence.basis: user_confirmed\n      idempotency_key: <stable key>\n      reason: <confirmed value without copying learned context>\n      run_key: *run_key\n  complete_or_decline:\n    tool: manage_onboarding\n    arguments:\n      action: resolve_obligation\n      programme_id: {}\n      generation: {generation}\n      resolution: <completed | declined>\n      evidence: <non-null evidence>\n      idempotency_key: <stable key>\n      reason: <why the terminal state is established>\n      run_key: *run_key", yaml_scalar(programme), yaml_scalar(programme));
    }
    out.push_str("```\n\nReuse the exact anchored run key on every subsequent Native call, reads included. It groups activity for continuity, inspection, and recovery; it is not a rollback command.\n");
}

fn render_bootstrap_world_items(
    out: &mut String,
    label: &str,
    value: &Value,
    scan_truncated: bool,
) {
    let items = array(value, "items");
    let shown = items.len() as i64;
    let total = integer(value, "total_count").unwrap_or(shown);
    let limit = integer(value, "limit")
        .map(|limit| format!(", limit {limit}"))
        .unwrap_or_default();
    let truncated = boolean(value, "truncated").unwrap_or(false);

    if scan_truncated {
        let _ = writeln!(
            out,
            "\n{label} ({total} observed in the bounded scan; showing {shown}{limit}; scan truncated, so more may exist):"
        );
    } else if truncated {
        let _ = writeln!(
            out,
            "\n{label} ({total} total; showing {shown}{limit}; preview truncated):"
        );
    } else {
        let _ = writeln!(out, "\n{label} ({total} total; showing {shown}{limit}):");
    }

    if items.is_empty() {
        out.push_str("- None shown.\n");
        return;
    }
    for item in items {
        let name = string(item, "name").unwrap_or_else(|| "Untitled".into());
        let id = string(item, "id").unwrap_or_default();
        let name_note = boolean(item, "name_truncated")
            .filter(|truncated| *truncated)
            .map(|_| " (name truncated)")
            .unwrap_or_default();
        let _ = write!(out, "- {name}{name_note} · {id}");
        if let Some(record_type) = string(item, "type") {
            let _ = write!(out, " · {record_type}");
            if let Some(kind) = string(item, "kind") {
                let kind_note = boolean(item, "kind_truncated")
                    .filter(|truncated| *truncated)
                    .map(|_| " (truncated)")
                    .unwrap_or_default();
                let _ = write!(out, "/{kind}{kind_note}");
            }
        }
        if let Some(activity) = string(item, "last_activity_at") {
            let _ = write!(out, " · activity {activity}");
        }
        out.push('\n');
    }
}

/// Returns whether callable next-step items were emitted, so that nothing
/// downstream claims steps were stated for a guidance-only section.
fn render_bootstrap_next_steps(
    out: &mut String,
    value: &Value,
    anchored_run_key: Option<&str>,
) -> bool {
    let items = array(value, "items");
    let guidance = string(value, "guidance");
    if items.is_empty() && guidance.is_none() {
        return false;
    }

    out.push_str("\n## Available next steps\n\n");
    if let Some(guidance) = guidance {
        let _ = writeln!(out, "{guidance}");
    }
    let shared_run_key = anchored_run_key.filter(|run_key| {
        !items.is_empty()
            && items.iter().all(|item| {
                item.pointer("/arguments/run_key").and_then(Value::as_str) == Some(*run_key)
            })
    });
    if shared_run_key.is_some() {
        out.push_str(
            "Each call uses the exact anchored `run_key` in the continuation block below.\n",
        );
    } else if !items.is_empty() {
        out.push_str("Arguments are shown in full because no single shared `run_key` was established for every step.\n");
    }
    for item in items {
        let label = string(item, "label").unwrap_or_else(|| "Continue".into());
        let tool = string(item, "tool").unwrap_or_else(|| "unknown".into());
        let _ = write!(out, "\n- {label} (`{tool}`)");
        if let Some(why) = string(item, "why") {
            let _ = write!(out, " — {why}");
        }
        out.push('\n');

        if let Some(arguments) = item.get("arguments").and_then(Value::as_object) {
            let mut arguments = arguments.clone();
            if shared_run_key.is_some() {
                arguments.remove("run_key");
            }
            if !arguments.is_empty() {
                let _ = writeln!(
                    out,
                    "  {}: {}",
                    if shared_run_key.is_some() {
                        "Arguments besides `run_key`"
                    } else {
                        "Arguments"
                    },
                    inline_json(&Value::Object(arguments))
                );
            }
        }
        let placeholders = array(item, "replace_placeholders");
        if !placeholders.is_empty() {
            let names = placeholders
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(out, "  Replace placeholders: {names}.");
        }
    }
    !items.is_empty()
}

fn render_bootstrap(value: &Value) -> String {
    let mut out = String::new();
    let instructions = value.get("instructions").unwrap_or(&Value::Null);
    let obligations = array(value, "pending_obligations");
    let relevant = obligations
        .iter()
        .filter(|obligation| relevant_first_use_obligation(obligation))
        .collect::<Vec<_>>();

    let orientation = value
        .pointer("/orientation/content")
        .and_then(Value::as_str)
        .or_else(|| bootstrap_engine_orientation(instructions));
    if let Some(body) = orientation {
        out.push_str(body);
        if !body.ends_with('\n') {
            out.push('\n');
        }
    }

    if let Some(status) = value.pointer("/tool_exposure/runtime").filter(|status| {
        status.get("contract").and_then(Value::as_str)
            == Some(crate::standby::STANDBY_STATUS_CONTRACT)
    }) {
        out.push('\n');
        out.push_str(&render_standby_status(status));
    }

    let invalid_instructions = string(instructions, "status").as_deref() != Some("ready");
    if invalid_instructions {
        out.push('\n');
        render_bootstrap_repair(&mut out, instructions, &relevant);
        let next_steps_stated = value.get("next_steps").is_some_and(|next_steps| {
            render_bootstrap_next_steps(
                &mut out,
                next_steps,
                value
                    .get("session")
                    .or_else(|| value.get("run"))
                    .and_then(|run| run.get("run_key"))
                    .and_then(Value::as_str),
            )
        });
        // The repair path returns before "Current footing", so nothing it would
        // have stated has been stated.
        render_internal_continuation(
            &mut out,
            value,
            None,
            FootingStated::default(),
            next_steps_stated,
        );
        return out;
    }

    out.push_str("\n## Current footing\n\nUse this footing internally for orientation and placement; do not announce it merely to prove the connection works.\n");
    if let Some(principal) = value.get("principal") {
        let name = string(principal, "display_name")
            .unwrap_or_else(|| "Authenticated human principal".into());
        // A person who has not renamed themselves is named after their address,
        // so printing both would read `richardcrng@gmail.com · richardcrng@gmail.com`.
        match string(principal, "email").filter(|email| *email != name) {
            Some(email) => {
                let _ = writeln!(out, "\nPrincipal: {name} · {email}");
            }
            None => {
                let _ = writeln!(out, "\nPrincipal: {name}");
            }
        }
        out.push_str("You act through a client for this person. You are not the principal.\n");
        if let Some(utc) = string(principal, "utc_datetime") {
            let _ = writeln!(out, "UTC observed at: {utc}");
        }
    }
    let mut footing = FootingStated::default();
    if let Some(workspace_name) = value
        .pointer("/workspace/primary_workspace/name")
        .and_then(Value::as_str)
    {
        let _ = writeln!(out, "\nWorkspace: {workspace_name}\nWorkspace root: `native:root`\nUnfiled workspace destination: `native:unfiled`");
        footing.destinations = true;
    }
    if let Some(private) = value
        .pointer("/principal/private_context/root_record_id")
        .and_then(Value::as_str)
    {
        let visibility = value
            .pointer("/principal/private_context/visibility")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let _ = writeln!(out, "Private agent context: `{private}` · {visibility}. Use it only when the person intentionally wants durable context kept private from the workspace.");
        footing.private_context = true;
    }

    out.push('\n');
    render_bootstrap_guidance(&mut out, instructions);
    if let Some(standing) = value.get("standing_context") {
        let boundaries = array(standing, "product_boundaries");
        if !boundaries.is_empty() {
            out.push_str("\n### Product boundaries\n\n");
            for boundary in boundaries.iter().filter_map(Value::as_str) {
                let _ = writeln!(out, "- {boundary}");
            }
        }
    }

    if let Some(world) = value.get("current_world") {
        out.push_str("\n## Current world\n\nThis is a bounded, point-in-time orientation, not proof that no other relevant state exists. Inspect more deeply when the person's request requires it.\n");
        if let Some(observed) = string(world, "observed_at") {
            let _ = writeln!(out, "\nObserved: {observed}");
        }
        let scan_truncated = boolean(world, "scan_truncated").unwrap_or(false);
        if let Some(scan_limit) = integer(world, "scan_limit") {
            let status = if scan_truncated {
                "reached; more candidates may exist"
            } else {
                "scan not truncated"
            };
            let _ = writeln!(out, "Candidate scan limit: {scan_limit} ({status}).");
        }
        if let Some(recent) = world.get("recent_activity") {
            render_bootstrap_world_items(
                &mut out,
                "Recent relevant activity",
                recent,
                scan_truncated,
            );
        }
        if let Some(open) = world.get("open_work") {
            render_bootstrap_world_items(&mut out, "Open work", open, scan_truncated);
        }
        if let Some(omitted) =
            integer(world, "omitted_unrepresentable_count").filter(|count| *count > 0)
        {
            let _ = writeln!(
                out,
                "\n{omitted} record(s) in the bounded scan could not be represented within Bootstrap's preview item bounds."
            );
        }
    }

    let onboarding = (relevant.len() == 1).then(|| relevant[0]);
    if relevant.len() > 1 {
        out.push('\n');
        render_bootstrap_repair(&mut out, instructions, &relevant);
    } else if let Some(obligation) = onboarding {
        out.push('\n');
        render_first_use_onboarding(&mut out, obligation);
    }

    let next_steps_stated = value.get("next_steps").is_some_and(|next_steps| {
        render_bootstrap_next_steps(
            &mut out,
            next_steps,
            value
                .get("session")
                .or_else(|| value.get("run"))
                .and_then(|run| run.get("run_key"))
                .and_then(Value::as_str),
        )
    });

    out.push_str("\n## Intentful sessions\n\nInfer a clear intent from the person's request instead of asking them to repeat it. Declare it separately with `set_intent`, and update it when the underlying aim materially changes. Intent connects work into an inspectable run and enables a purpose-relative briefing; it is not a claim or permission.\n");
    render_internal_continuation(&mut out, value, onboarding, footing, next_steps_stated);
    out
}

fn render_quickstart(value: &Value) -> String {
    let _ = value;
    crate::mcp::tools::quickstart::MARKDOWN.to_string()
}

// ---------------------------------------------------------------------------
// get_structure
// ---------------------------------------------------------------------------

fn render_structure(value: &Value) -> String {
    let mut out = temporal_header(value);
    let nodes = array(value, "nodes");
    let max_depth = integer(value, "max_depth").unwrap_or_default();
    let max_children = integer(value, "max_children_per_node").unwrap_or_default();
    let _ = writeln!(
        out,
        "{} node(s) from {} — max_depth {max_depth}, max {max_children} children/node",
        nodes.len(),
        string(value, "root_id").unwrap_or_default(),
    );

    // Indent by depth. A node whose child_count exceeds the children actually
    // emitted below it is marked: the cap is the difference between "this is a
    // leaf" and "you were shown a page of it", and only the payload knows.
    let mut emitted_children = std::collections::HashMap::<String, i64>::new();
    for node in nodes {
        if let Some(parent) = string(node, "home_id") {
            *emitted_children.entry(parent).or_default() += 1;
        }
    }
    for node in nodes {
        let depth = integer(node, "depth").unwrap_or(0).max(0) as usize;
        let id = string(node, "id").unwrap_or_default();
        let _ = write!(
            out,
            "{}{}  {}  {}",
            "  ".repeat(depth + 1),
            id,
            type_label(node),
            string(node, "name").unwrap_or_default(),
        );
        let child_count = integer(node, "child_count").unwrap_or(0);
        let shown = emitted_children.get(&id).copied().unwrap_or(0);
        if child_count > shown {
            let _ = write!(out, "  ({child_count} children, {shown} shown)");
        }
        if node.get("archived").and_then(Value::as_bool) == Some(true) {
            out.push_str("  [archived]");
        }
        out.push('\n');
        let details = json!({
            "home_id": node.get("home_id"),
            "persistence": node.get("persistence"),
            "last_activity_at": node.get("last_activity_at"),
            "custody_boundary": node.get("custody_boundary"),
            "containment_path_visible": node.get("containment_path_visible"),
        });
        let _ = writeln!(
            out,
            "{}details: {}",
            "  ".repeat(depth + 2),
            inline_json(&details)
        );
    }
    out
}

// ---------------------------------------------------------------------------
// get_dashboard
// ---------------------------------------------------------------------------

/// One dashboard/query row: id, type, name, then whatever state it carries.
fn preferred_record_url(record: &Value) -> Option<String> {
    string(record, "share_url").or_else(|| string(record, "record_url"))
}

fn linked_record_name(record: &Value) -> String {
    let name = string(record, "name").unwrap_or_default();
    let mut escaped = String::with_capacity(name.len());
    for character in name.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '[' => escaped.push_str("\\["),
            ']' => escaped.push_str("\\]"),
            character if character.is_control() => escaped.extend(character.escape_default()),
            character => escaped.push(character),
        }
    }
    let Some(url) = preferred_record_url(record) else {
        return escaped;
    };
    format!("[{escaped}]({url})")
}

fn record_line(record: &Value, id_width: usize, type_width: usize) -> String {
    let id = display_inline(&string(record, "id").unwrap_or_default());
    let mut line = format!(
        "  {}  {}  {}",
        pad(&id, id_width),
        pad(&type_label(record), type_width),
        linked_record_name(record),
    );
    let mut state = lifecycle_display(record)
        .map(|value| display_inline(&value))
        .into_iter()
        .collect::<Vec<_>>();
    state.extend(string(record, "maturity").map(|value| display_inline(&value)));
    if let Some(activity) = string(record, "last_activity_at") {
        state.push(format!("activity {}", display_inline(&activity)));
    }
    if !state.is_empty() {
        let _ = write!(line, "  [{}]", state.join(", "));
    }
    line
}

fn render_dashboard(value: &Value) -> String {
    let mut out = String::new();
    let stale_after = integer(value, "stale_after_days").unwrap_or_default();
    match string(value, "scope") {
        Some(scope) => {
            let _ = write!(out, "Dashboard for subtree {scope}");
        }
        None => out.push_str("Dashboard for the whole database"),
    }
    let limit = integer(value, "limit").unwrap_or_default();
    let _ = writeln!(
        out,
        " · stale after {stale_after}d · per-bucket limit {limit}"
    );
    if let Some(cutoff) = value.get("stale_cutoff") {
        let _ = writeln!(out, "Exact stale cutoff: {}", inline_json(cutoff));
    }

    for (heading, key, total_key) in [
        ("Active", "active", "active_total"),
        ("Stale", "stale", "stale_total"),
        ("Blocked", "blocked", "blocked_total"),
    ] {
        let rows = array(value, key);
        let total = integer(value, total_key).unwrap_or(rows.len() as i64);
        out.push('\n');
        if rows.is_empty() {
            let _ = writeln!(out, "{heading}: none (0 shown of {total} total)");
            continue;
        }
        let _ = writeln!(out, "{heading} ({} shown of {total} total)", rows.len());
        let id_width = column_width(rows, |row| string(row, "id").unwrap_or_default());
        let type_width = column_width(rows, type_label);
        for row in rows {
            let _ = write!(out, "{}", record_line(row, id_width, type_width));
            // The blocked bucket's whole value is WHICH record blocks it; a
            // rendering that said "blocked" without naming the blocker would
            // force a second call to act on the first.
            for (label, edge) in [("blocked by", "blocked_by"), ("waiting on", "waiting_on")] {
                let edges = array(row, edge);
                if !edges.is_empty() {
                    let _ = write!(out, "  ({label} {})", inline_json(&json!(edges)));
                }
            }
            out.push('\n');
            if let Some(interpretation) = row.get("lifecycle_interpretation") {
                let _ = writeln!(
                    out,
                    "    lifecycle_interpretation: {}",
                    inline_json(interpretation)
                );
            }
        }
    }

    // A governance gap, reported as a footnote to the buckets rather than as
    // one of them. Phrased so it cannot be read as a fourth destination:
    // every record listed here was already shown above.
    let unclassified = value
        .get("unclassified_lifecycle")
        .cloned()
        .unwrap_or(Value::Null);
    let unclassified_total = integer(&unclassified, "total_count").unwrap_or_default();
    if let Some(note) = unclassified.get("note") {
        let _ = writeln!(
            out,
            "\nUnclassified lifecycle diagnostic note: {}",
            inline_json(note)
        );
    }
    if unclassified_total > 0 {
        let items = array(&unclassified, "items");
        out.push('\n');
        let _ = writeln!(
            out,
            "Unclassified lifecycle ({} of {unclassified_total} shown) — these records are \
             listed above; the engine could not interpret their lifecycle:",
            items.len()
        );
        for row in items {
            let _ = writeln!(out, "  {}", inline_json(row));
        }
    }

    // The census counts the scope, not the buckets above — it is the only
    // number here that is not windowed by `limit`.
    let census = value
        .get("lifecycle_census")
        .cloned()
        .unwrap_or(Value::Null);
    let buckets = array(&census, "buckets");
    if !buckets.is_empty() {
        let listed = buckets
            .iter()
            .map(|bucket| {
                let key = string(bucket, "key").unwrap_or_else(|| "(none)".into());
                let count = integer(bucket, "count").unwrap_or_default();
                format!("{key} {count}")
            })
            .collect::<Vec<_>>()
            .join(" · ");
        out.push('\n');
        let _ = writeln!(
            out,
            "Lifecycle census ({} records in scope): {listed}",
            integer(&census, "total").unwrap_or_default()
        );
    }
    if !census.is_null() {
        let _ = writeln!(out, "Lifecycle census details: {}", inline_json(&census));
    }
    out
}

// ---------------------------------------------------------------------------
// describe_schema
// ---------------------------------------------------------------------------

fn render_describe_schema(value: &Value) -> String {
    let mut out = String::new();
    let engine = value.get("engine").cloned().unwrap_or(Value::Null);
    let _ = writeln!(
        out,
        "{} {} · engine schema {}",
        string(&engine, "name").unwrap_or_default(),
        string(&engine, "version").unwrap_or_default(),
        integer(&engine, "schema_version").unwrap_or_default(),
    );
    let _ = writeln!(out, "Engine contract: {}", inline_json(&engine));

    // The authority model leads: it is the reason to read this before
    // query_sql, and the one thing a table listing alone cannot convey.
    if let Some(model) = string(value, "model") {
        let (preview, changed) = one_line_preview(&model, 400);
        let _ = writeln!(out, "\n{preview}");
        if changed {
            let _ = writeln!(
                out,
                "(Model text shortened; call describe_schema with format:\"json\" for the full value.)"
            );
        }
    }

    // Grouped by role, because the role is the actionable axis — "may I write
    // this?" — and repeating a long role string per table costs more than the
    // grouping saves.
    let tables = array(value, "tables");
    let mut roles: Vec<(String, Vec<String>)> = Vec::new();
    for table in tables {
        let role = string(table, "role").unwrap_or_default();
        let name = string(table, "name").unwrap_or_default();
        let columns = array(table, "columns").len();
        let entry = format!("{name}({columns})");
        match roles.iter_mut().find(|(existing, _)| *existing == role) {
            Some((_, names)) => names.push(entry),
            None => roles.push((role, vec![entry])),
        }
    }
    for (role, names) in &roles {
        let _ = writeln!(out, "\n{role}\n  {}", names.join(" · "));
    }
    let _ = writeln!(
        out,
        "\n{} table(s), name(column count). Call with format:\"json\" for every column's \
         name, type, nullability and primary-key flag.",
        tables.len()
    );
    if let Some(ddl) = value.get("ddl_statements").and_then(Value::as_array) {
        let _ = writeln!(out, "\nFrozen DDL ({} statement(s)):", ddl.len());
        for (index, statement) in ddl.iter().filter_map(Value::as_str).enumerate() {
            let _ = writeln!(out, "\n--- statement {} ---", index + 1);
            out.push_str(statement);
            if !statement.ends_with('\n') {
                out.push('\n');
            }
        }
    }
    if let Some(resolved) = value.get("resolved_schema_config") {
        let _ = writeln!(out, "\nResolved schema config: {}", inline_json(resolved));
    }
    if let Some(registry) = value.get("kind_registry") {
        let _ = writeln!(out, "\nKind registry: {}", inline_json(registry));
    }
    out
}

// ---------------------------------------------------------------------------
// preview_record_shape
// ---------------------------------------------------------------------------

fn collect_preview_omissions<'a>(value: &'a Value, found: &mut Vec<&'a Value>) {
    if let Some(omitted) = value.get("omitted") {
        found.push(omitted);
        return;
    }
    match value {
        Value::Array(values) => {
            for value in values {
                collect_preview_omissions(value, found);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_preview_omissions(value, found);
            }
        }
        _ => {}
    }
}

fn canvas_geometry(object: &Value) -> String {
    ["x", "y", "w", "h"]
        .iter()
        .map(|key| match object.get(*key).and_then(Value::as_f64) {
            Some(number) => format!("{number}"),
            None => "?".to_string(),
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn canvas_actor_label(actor: Option<&Value>) -> String {
    match actor {
        Some(Value::Object(actor)) => match actor
            .get("display_name")
            .and_then(Value::as_str)
            .or_else(|| actor.get("id").and_then(Value::as_str))
        {
            Some(label) => display_inline(label),
            None => "(actor unreadable)".to_string(),
        },
        _ => "(actor undisclosed)".to_string(),
    }
}

fn render_read_canvas(value: &Value) -> String {
    let mut out = String::new();
    let canvas = claimed_string(value.get("canvas_id"), "canvas id");
    let version = claimed_string(value.get("canvas_version"), "canvas version");
    match value.get("action").and_then(Value::as_str) {
        Some("get_scene") => {
            let objects = array(value, "objects");
            let _ = writeln!(
                out,
                "Canvas {canvas} at {version}: {} live object(s), {} listed",
                claimed_integer(value.get("live_objects"), "live object count"),
                objects.len()
            );
            for object in objects.iter().take(200) {
                let mut line = format!(
                    "- {} {} [{}]",
                    claimed_string(object.get("id"), "object id"),
                    claimed_string(object.get("kind"), "kind"),
                    canvas_geometry(object)
                );
                if let Some(text) = object.pointer("/props/text").and_then(Value::as_str) {
                    let short = text.chars().take(60).collect::<String>();
                    let _ = write!(line, " \"{}\"", display_inline(&short));
                }
                if let Some(record) = object.get("record") {
                    let _ = write!(
                        line,
                        " -> {} ({})",
                        claimed_string(record.get("name"), "record name"),
                        claimed_string(record.get("id"), "record id")
                    );
                } else if object.pointer("/props/record_id").and_then(Value::as_str)
                    == Some("withheld")
                {
                    line.push_str(" -> record withheld");
                }
                if object.get("deleted") == Some(&Value::Bool(true)) {
                    line.push_str(" (deleted)");
                }
                let _ = writeln!(out, "{line}");
            }
            if objects.len() > 200 {
                let _ = writeln!(
                    out,
                    "... {} more object(s) in structuredContent",
                    objects.len() - 200
                );
            }
        }
        Some("changes") => {
            let batches = array(value, "batches");
            let _ = writeln!(
                out,
                "Canvas {canvas} at {version}: {} batch(es) after {}{}",
                batches.len(),
                claimed_string(value.get("after"), "after"),
                if value.get("more") == Some(&Value::Bool(true)) {
                    ", more available"
                } else {
                    ""
                }
            );
            for batch in batches.iter().take(200) {
                let _ = writeln!(
                    out,
                    "- {} {} by {} at {}: {} op(s), origin {}",
                    claimed_string(batch.get("canvas_version"), "version"),
                    claimed_string(batch.get("batch_id"), "batch id"),
                    canvas_actor_label(batch.get("actor")),
                    claimed_string(batch.get("at"), "time"),
                    array(batch, "ops").len(),
                    claimed_string(batch.pointer("/origin/kind"), "origin kind")
                );
            }
            if let Some(next) = batch_next_after(value) {
                let _ = writeln!(out, "Continue with after: {next}");
            }
        }
        _ => {
            let _ = writeln!(
                out,
                "Canvas response was not interpreted; see structuredContent."
            );
        }
    }
    out
}

fn batch_next_after(value: &Value) -> Option<String> {
    value
        .get("next_after")
        .and_then(Value::as_str)
        .map(display_inline)
}

fn render_manage_canvas(value: &Value) -> String {
    let mut out = String::new();
    let batch = claimed_string(value.get("batch_id"), "batch id");
    let version = claimed_string(value.get("canvas_version"), "canvas version");
    match value.get("outcome").and_then(Value::as_str) {
        Some(outcome @ ("committed" | "replayed")) => {
            let objects = value
                .get("objects")
                .and_then(Value::as_object)
                .map(|objects| objects.len().to_string())
                .unwrap_or_else(|| "(object versions not reported)".to_string());
            let _ = writeln!(
                out,
                "Batch {batch} {outcome} at {version}: {objects} object version(s) in structuredContent.objects"
            );
        }
        Some("conflict") => {
            let conflicts = array(value, "conflicts");
            let _ = writeln!(
                out,
                "Batch {batch} conflicted at {version}; nothing was written. {} precondition(s) failed:",
                conflicts.len()
            );
            for conflict in conflicts.iter().take(50) {
                let group = match conflict.get("group").and_then(Value::as_str) {
                    Some(group) => format!(" ({})", display_inline(group)),
                    None => String::new(),
                };
                let _ = writeln!(
                    out,
                    "- {} {}{}, last moved by {}",
                    claimed_string(conflict.get("id"), "object id"),
                    claimed_string(conflict.get("code"), "code"),
                    group,
                    canvas_actor_label(conflict.get("competing_actor"))
                );
            }
            out.push_str(
                "Re-read current versions from structuredContent.conflicts[].current and retry.\n",
            );
        }
        Some("rejected") => {
            let _ = writeln!(
                out,
                "Batch {batch} rejected: {} - {}",
                claimed_string(value.pointer("/error/code"), "error code"),
                claimed_string(value.pointer("/error/message"), "error message")
            );
            out.push_str("Nothing was written; do not repeat the batch unchanged.\n");
        }
        _ => {
            out.push_str("Canvas write response has no valid outcome and was not interpreted; exact response remains in structuredContent.\n");
        }
    }
    out
}

fn render_record_shape_preview(value: &Value) -> String {
    let mut out = String::from("Advisory record-shape preview\n");
    let types = value
        .pointer("/catalogs/types")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let _ = writeln!(out, "\nSpine types ({}):", types.len());
    for entry in types.iter().take(20) {
        let record_type = string(entry, "type").unwrap_or_default();
        let gloss = string(entry, "short_gloss")
            .or_else(|| string(entry, "gloss"))
            .unwrap_or_default();
        let _ = writeln!(out, "  {record_type} — {}", one_line(&gloss, 180));
    }

    if let Some(selection) = value.get("selection").filter(|value| !value.is_null()) {
        let record_type = string(selection, "type").unwrap_or_default();
        let kind = string(selection, "kind");
        let effective_kind = string(selection, "effective_kind");
        let _ = writeln!(
            out,
            "\nSelection: {record_type}{}{}",
            kind.as_deref()
                .map(|kind| format!(" / {}", one_line(kind, 120)))
                .unwrap_or_default(),
            effective_kind
                .as_deref()
                .filter(|effective| Some(*effective) != kind.as_deref())
                .map(|effective| format!(" · effective kind {}", one_line(effective, 120)))
                .unwrap_or_default(),
        );
        if selection.pointer("/details/omitted").is_some() {
            out.push_str(
                "Active governed kinds: selection details omitted from this bounded response; see omissions below.\n",
            );
        } else if selection.pointer("/active_kinds/omitted").is_some() {
            out.push_str(
                "Active governed kinds: listing omitted from this bounded response; see omissions below.\n",
            );
        } else {
            let active_kinds = array(selection, "active_kinds");
            let _ = writeln!(out, "Active governed kinds: {}", active_kinds.len());
        }

        if let Some(resolution) = selection
            .get("kind_resolution")
            .filter(|value| !value.is_null())
        {
            if resolution.get("omitted").is_none() {
                let classification =
                    string(resolution, "classification").unwrap_or_else(|| "unknown".into());
                let canonical = string(resolution, "canonical_kind")
                    .map(|kind| format!(" · canonical {kind}"))
                    .unwrap_or_default();
                let quarantined =
                    boolean(resolution, "quarantined").is_some_and(|quarantined| quarantined);
                let _ = writeln!(
                    out,
                    "Kind resolution: {classification}{canonical}{}",
                    if quarantined { " · quarantined" } else { "" }
                );
                if let Some(warning) = string(resolution, "warning") {
                    let _ = writeln!(out, "Kind warning: {}", one_line(&warning, 400));
                }
            }
        }

        if selection
            .pointer("/effective_facet_shape/omitted")
            .is_some()
        {
            out.push_str("Facets: omitted from this bounded response; see omissions below.\n");
        } else if let Some(facets) = selection
            .get("effective_facet_shape")
            .and_then(Value::as_object)
        {
            let _ = writeln!(out, "Facets ({}):", facets.len());
            for (key, shape) in facets.iter().take(24) {
                let _ = writeln!(
                    out,
                    "  {}: {}",
                    one_line(key, 120),
                    one_line(&inline_json(shape), 180)
                );
            }
            if facets.len() > 24 {
                let _ = writeln!(
                    out,
                    "  … {} more facet(s); use format:\"json\" for the complete bounded value.",
                    facets.len() - 24
                );
            }
        }
        if let Some(spine_facets) = selection.get("spine_facets") {
            let _ = writeln!(
                out,
                "Spine facets: {}",
                one_line(&inline_json(spine_facets), 400)
            );
        }
    } else {
        out.push_str("\nSelection: none (catalog-only preview).\n");
    }

    if let Some(proposed) = value.get("proposed_facets") {
        let status = string(proposed, "status").unwrap_or_else(|| "unknown".into());
        let assessments = array(proposed, "assessments");
        let _ = writeln!(
            out,
            "\nProposed facets: {status} ({} supplied)",
            assessments.len()
        );
        for assessment in assessments {
            let key = string(assessment, "key").unwrap_or_else(|| "unknown".into());
            let status = string(assessment, "status").unwrap_or_else(|| "unknown".into());
            let declaration = string(assessment, "declaration").unwrap_or_else(|| "unknown".into());
            let issues = join_strings(array(assessment, "issues"));
            let suffix = if issues.is_empty() {
                String::new()
            } else {
                format!(" · issues {issues}")
            };
            let _ = writeln!(
                out,
                "  {} — {status} · {declaration}{suffix}",
                one_line(&key, 120)
            );
            if let Some(vocabulary) = assessment
                .get("governing_vocabulary")
                .filter(|value| !value.is_null())
            {
                let id = string(vocabulary, "id").unwrap_or_else(|| "unknown".into());
                let name = string(vocabulary, "name");
                let _ = writeln!(
                    out,
                    "    vocabulary: {}{}",
                    one_line(&id, 120),
                    name.map(|name| format!(" ({})", one_line(&name, 120)))
                        .unwrap_or_default()
                );
            }
            if let Some(resolution) = assessment
                .get("value_resolution")
                .filter(|value| !value.is_null())
            {
                let classification =
                    string(resolution, "classification").unwrap_or_else(|| "unknown".into());
                let status = string(resolution, "status")
                    .map(|status| format!(" · status {status}"))
                    .unwrap_or_default();
                let _ = writeln!(out, "    value resolution: {classification}{status}");
            }
        }
        let required = array(proposed, "required_declarations");
        if !required.is_empty() {
            let _ = writeln!(out, "Required declarations (informational):");
            for declaration in required {
                let key = string(declaration, "key").unwrap_or_else(|| "unknown".into());
                let presence =
                    string(declaration, "candidate_presence").unwrap_or_else(|| "unknown".into());
                let input = declaration
                    .pointer("/create_record_input/field")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let _ = writeln!(
                    out,
                    "  {} — {presence} · create_record field {}",
                    one_line(&key, 120),
                    one_line(input, 120)
                );
            }
        }
    }

    let basis = value.get("advisory_basis").unwrap_or(&Value::Null);
    let semantic = basis.get("semantic_contract").unwrap_or(&Value::Null);
    let _ = writeln!(
        out,
        "\nAdvisory basis: engine schema {} · state {}",
        integer(basis, "engine_schema_version").unwrap_or_default(),
        string(basis, "schema_state_revision").unwrap_or_else(|| "unknown".into()),
    );
    if let Some(revision) = string(semantic, "revision") {
        let digest = string(semantic, "sha256").unwrap_or_default();
        let _ = writeln!(out, "Semantic contract: {revision} · sha256 {digest}");
    }
    if let Some(global) = basis.get("global_schema") {
        let _ = writeln!(
            out,
            "Global schema: {} row(s) · {} byte(s) · sha256 {}",
            integer(global, "row_count").unwrap_or_default(),
            integer(global, "utf8_bytes").unwrap_or_default(),
            string(global, "sha256").unwrap_or_default(),
        );
    }
    let advisory_only = boolean(value, "advisory_only").unwrap_or(false);
    let accepted_by_create = boolean(value, "accepted_by_create_record").unwrap_or(false);
    let zero_authoritative_writes = boolean(value, "zero_authoritative_writes").unwrap_or(false);
    let _ = writeln!(
        out,
        "Contract flags: advisory_only={advisory_only} · accepted_by_create_record={accepted_by_create} · zero_authoritative_writes={zero_authoritative_writes}",
    );
    if let Some(guarantee) = string(value, "guarantee") {
        let _ = writeln!(out, "Guarantee: {}", one_line(&guarantee, 400));
    }

    let not_checked = array(value, "not_checked");
    if !not_checked.is_empty() {
        let _ = writeln!(out, "Not checked: {}", join_strings(not_checked));
    }

    let mut omissions = Vec::new();
    collect_preview_omissions(value, &mut omissions);
    if !omissions.is_empty() {
        let _ = writeln!(out, "\nOmissions ({}):", omissions.len());
        for omitted in omissions.iter().take(12) {
            let identity = string(omitted, "identity").unwrap_or_else(|| "unknown".into());
            let bytes = integer(omitted, "utf8_bytes").unwrap_or_default();
            let digest = string(omitted, "sha256").unwrap_or_default();
            let _ = writeln!(out, "  {identity} · {bytes} byte(s) · sha256 {digest}");
        }
        if omissions.len() > 12 {
            let _ = writeln!(out, "  … {} more omission marker(s).", omissions.len() - 12);
        }
        out.push_str("Use the structured continuation in format:\"json\" to inspect an omitted definition.\n");
    }
    // The handler has already bounded this response and replaced oversized
    // authored fragments with explicit omission continuations. Preserve that
    // exact bounded decision surface in text: the compact summary above is for
    // orientation, while these projections carry catalog metadata, kind
    // matches/provenance, event heads, scope, and the decision digest used to
    // compare previews safely.
    for (label, key) in [
        ("Response schema", "schema"),
        ("Exact bounded catalogs", "catalogs"),
        ("Exact bounded selection", "selection"),
        ("Exact advisory basis", "advisory_basis"),
    ] {
        if let Some(found) = value.get(key) {
            let _ = writeln!(out, "{label}: {}", inline_json(found));
        }
    }
    render_fields(
        &mut out,
        value,
        &[
            "schema",
            "catalogs",
            "selection",
            "advisory_basis",
            "advisory_only",
            "accepted_by_create_record",
            "zero_authoritative_writes",
            "guarantee",
            "not_checked",
            "run_context",
        ],
    );
    out
}

#[cfg(test)]
mod record_shape_preview_tests {
    use super::*;

    fn omitted(identity: &str) -> Value {
        json!({
            "omitted": {
                "identity": identity,
                "sha256": "0".repeat(64),
                "utf8_bytes": 70_000,
                "continuation": {},
            }
        })
    }

    #[test]
    fn omitted_active_kind_listing_is_never_rendered_as_zero() {
        let rendered = render_record_shape_preview(&json!({
            "catalogs": { "types": [] },
            "selection": {
                "type": "Document",
                "active_kinds": omitted("active_kind_definitions:Document"),
            },
            "advisory_basis": {},
        }));
        assert!(rendered.contains("Active governed kinds: listing omitted"));
        assert!(!rendered.contains("Active governed kinds: 0"));
    }

    #[test]
    fn compacted_whole_selection_is_never_rendered_as_zero_kinds() {
        let rendered = render_record_shape_preview(&json!({
            "catalogs": { "types": [] },
            "selection": {
                "type": "Document",
                "details": omitted("record_shape_selection:Document"),
            },
            "advisory_basis": {},
        }));
        assert!(rendered.contains("Active governed kinds: selection details omitted"));
        assert!(!rendered.contains("Active governed kinds: 0"));
    }
}

// ---------------------------------------------------------------------------
// get_record
// ---------------------------------------------------------------------------

fn render_comment_target(out: &mut String, comment: &Value, indent: &str) {
    let Some(target) = comment.get("target").and_then(Value::as_object) else {
        return;
    };
    let status = target
        .get("validation")
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("unavailable");
    let excerpt = target
        .get("anchored")
        .and_then(|value| value.get("excerpt"))
        .and_then(|value| value.get("text"))
        .and_then(Value::as_str);
    if let Some(excerpt) = excerpt {
        let (preview, shortened) = one_line_preview(excerpt, 240);
        let _ = writeln!(
            out,
            "{indent}Anchored passage [{status}]: {preview}{}",
            if shortened {
                " (excerpt shortened; use format:\"json\")"
            } else {
                ""
            }
        );
    } else {
        let _ = writeln!(out, "{indent}Anchored passage [{status}]: unavailable");
    }
}

fn exact_object_remainder(value: &Value, rendered_keys: &[&str]) -> Option<Value> {
    let remainder = value
        .as_object()?
        .iter()
        .filter(|(key, _)| !rendered_keys.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Map<_, _>>();
    (!remainder.is_empty()).then_some(Value::Object(remainder))
}

fn exact_known_object_remainder(
    value: &Value,
    rendered_keys: &[&str],
    known: impl Fn(&str) -> bool,
) -> Option<Value> {
    let remainder = value
        .as_object()?
        .iter()
        .filter(|(key, _)| known(key) && !rendered_keys.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Map<_, _>>();
    (!remainder.is_empty()).then_some(Value::Object(remainder))
}

fn unknown_object_keys(value: &Value, known: impl Fn(&str) -> bool) -> Vec<String> {
    value
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(key, _)| !known(key))
        .map(|(key, _)| key.clone())
        .collect()
}

fn render_get_record(value: &Value, include_response_scope: bool) -> String {
    let mut out = temporal_header(value);
    let records = array(value, "records");
    let multiple = records.len() > 1;
    let children_limit = integer(value, "children_limit").unwrap_or_default();
    let children_offset = integer(value, "children_offset").unwrap_or_default();
    let links_limit = integer(value, "links_limit").unwrap_or_default();
    let links_offset = integer(value, "links_offset").unwrap_or_default();
    let suggestions_limit = integer(value, "suggestions_limit").unwrap_or_default();
    let suggestions_offset = integer(value, "suggestions_offset").unwrap_or_default();
    let citations_limit = integer(value, "citations_limit").unwrap_or_default();
    let citations_offset = integer(value, "citations_offset").unwrap_or_default();
    let comments_limit = integer(value, "comments_limit").unwrap_or_default();
    let comments_offset = integer(value, "comments_offset").unwrap_or_default();
    if include_response_scope {
        if let Some(scope) = exact_known_object_remainder(
            value,
            &[
                "records",
                "run_context",
                "resolved_content_seq",
                "content_head_seq",
                "as_of",
            ],
            is_get_record_response_field,
        ) {
            let _ = writeln!(out, "Read scope: {}", inline_json(&scope));
        }
        let unknown = unknown_object_keys(value, is_get_record_response_field);
        if !unknown.is_empty() {
            let _ = writeln!(
                out,
                "Additional response fields omitted from text: {}; re-call this read with the same arguments and format:\"json\" for exact values.",
                inline_json(&json!(unknown))
            );
        }
    }
    // Ancestor blocks are response-wide: identical text is emitted once and
    // referenced by the id of the record that carried it.
    let mut rendered_ancestors: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for (index, item) in records.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        // Partial success is per item: a batch where one id missed still
        // answers for the rest, and the rendering has to say which missed.
        if string(item, "status").as_deref() == Some("not_found") {
            let id = display_inline(&string(item, "id").unwrap_or_default());
            let _ = writeln!(out, "{id}  NOT FOUND");
            let unknown = unknown_object_keys(item, |key| matches!(key, "status" | "id"));
            if !unknown.is_empty() {
                let _ = writeln!(
                    out,
                    "  Additional not-found fields omitted from text: {}; re-call this read with the same arguments and format:\"json\" for exact values.",
                    inline_json(&json!(unknown))
                );
            }
            continue;
        }
        let _ = write!(
            out,
            "{}  {}  {}",
            display_inline(&string(item, "id").unwrap_or_default()),
            type_label(item),
            linked_record_name(item),
        );
        if item.get("archived").and_then(Value::as_bool) == Some(true) {
            out.push_str("  [archived]");
        }
        if item.get("bears_shape").and_then(Value::as_bool) == Some(true) {
            out.push_str("  [bears-shape]");
        }
        if item.get("has_query").and_then(Value::as_bool) == Some(true) {
            out.push_str("  [has-query]");
        }
        if let Some(deleted) = string(item, "deleted_at") {
            let _ = write!(out, "  [deleted {}]", display_inline(&deleted));
        }
        out.push('\n');

        // State line: the spine facets that are set, plus activity. Absent
        // facets are omitted rather than printed as null — an unset lifecycle
        // is not a value worth a token.
        let mut state = Vec::new();
        if let Some(found) = lifecycle_display(item) {
            state.push(format!("lifecycle {}", display_inline(&found)));
        }
        for (label, key) in [
            ("maturity", "maturity"),
            ("persistence", "persistence"),
            ("owner", "owner_id"),
        ] {
            if let Some(found) = string(item, key) {
                state.push(format!("{label} {}", display_inline(&found)));
            }
        }
        if let Some(activity) = string(item, "last_activity_at") {
            state.push(format!("activity {}", display_inline(&activity)));
        }
        if !state.is_empty() {
            let _ = writeln!(out, "  {}", state.join(" · "));
        }
        if let Some(details) = exact_known_object_remainder(
            item,
            &[
                "status",
                "id",
                "type",
                "kind",
                "name",
                "body",
                "owner_id",
                "persistence",
                "maturity",
                "summary",
                "last_activity_at",
                "deleted_at",
                "facets",
                "links_out",
                "links_in",
                "children",
                "suggestions",
                "citations",
                "comments",
                "target",
                "ancestors",
                "interpretation",
                "query_resolution",
            ],
            is_record_render_field,
        ) {
            let label = if value.get("as_of").is_some() {
                "Record details (historical projection with live-at-read-time enrichments)"
            } else {
                "Record details"
            };
            let _ = writeln!(out, "  {label}: {}", inline_json(&details));
        }
        let unknown = unknown_object_keys(item, is_record_render_field);
        if !unknown.is_empty() {
            let _ = writeln!(
                out,
                "  Additional record fields omitted from text: {}; re-call this read with the same arguments and format:\"json\" for exact values.",
                inline_json(&json!(unknown))
            );
        }
        let facets = array(item, "facets");
        if !facets.is_empty() {
            let _ = writeln!(out, "  Facets ({} complete):", facets.len());
            for facet in facets {
                let _ = writeln!(out, "    {}", inline_json(facet));
            }
        }
        if let Some(interpretation) = item.get("interpretation") {
            render_interpretation_summary(&mut out, interpretation, "  ");
            out.push_str(
                "  Interpretation details summarized; use format:\"json\" for the exact projection.\n",
            );
        }

        if let Some(resolution) = item.get("query_resolution") {
            let status = display_inline(&string(resolution, "status").unwrap_or_default());
            let version = string(resolution, "version")
                .map(|version| format!(" v{}", display_inline(&version)))
                .unwrap_or_default();
            match status.as_str() {
                "resolved" => {
                    let _ = writeln!(out, "  Query resolution{version}:");
                    if let Some(output) = resolution.get("output") {
                        for line in render_query_record(output).lines() {
                            let _ = writeln!(out, "    {line}");
                        }
                    }
                }
                _ => {
                    let diagnostic =
                        display_inline(&string(resolution, "diagnostic").unwrap_or_default());
                    let _ = writeln!(out, "  Query resolution{version}: {status} — {diagnostic}");
                }
            }
            out.push_str(
                "  Query resolution details summarized; use format:\"json\" for the exact projection.\n",
            );
        }

        // Where it sits. Root first, matching the payload's own order.
        let ancestors = array(item, "ancestors");
        if !ancestors.is_empty() {
            let path = ancestors
                .iter()
                .map(linked_record_name)
                .collect::<Vec<_>>()
                .join(" > ");
            let heading = match item
                .get("containment_path_visible")
                .and_then(Value::as_bool)
            {
                Some(true) => "Path (complete)",
                Some(false) => "Visible path fragment (containment path incomplete or withheld)",
                None => "Visible path (completeness not reported)",
            };
            let _ = writeln!(out, "  {heading}: {path}");
        }

        if let Some(summary) = string(item, "summary") {
            let (preview, changed) = one_line_preview(&summary, 300);
            let _ = writeln!(out, "  Summary: {preview}");
            if changed {
                let _ = writeln!(
                    out,
                    "    (Summary shortened; call get_record with format:\"json\" for the full value.)"
                );
            }
        }
        render_comment_target(&mut out, item, "  ");
        if let Some(target) = item.get("target") {
            let _ = writeln!(out, "  Target details: {}", inline_json(target));
        }

        // Totals over windows: `child_count` and `links_*_count` are the truth
        // about the record; the lists below them are a page.
        let children = array(item, "children");
        let child_count = integer(item, "child_count").unwrap_or(0);
        if child_count > 0 {
            render_window_heading(
                &mut out,
                "Children",
                child_count,
                children.len() as i64,
                children_offset,
                children_limit,
                "children_offset",
                "children_limit",
            );
            for child in children {
                let _ = writeln!(out, "    {}", inline_json(child));
            }
        }
        let suggestion_count = integer(item, "suggestion_count").unwrap_or(0);
        if suggestion_count > 0 {
            let suggestions = array(item, "suggestions");
            let included = boolean(value, "include_suggestions").unwrap_or(!suggestions.is_empty());
            if !included {
                let _ = writeln!(
                    out,
                    "  Suggestions: {suggestion_count} hidden (re-read with include_suggestions:true)"
                );
            } else {
                render_window_heading(
                    &mut out,
                    "Suggestions",
                    suggestion_count,
                    suggestions.len() as i64,
                    suggestions_offset,
                    suggestions_limit,
                    "suggestions_offset",
                    "suggestions_limit",
                );
                for suggestion in suggestions {
                    let _ = writeln!(out, "    {}", inline_json(suggestion));
                }
            }
        }
        let citation_count = integer(item, "citation_count").unwrap_or(0);
        if citation_count > 0 {
            let citations = array(item, "citations");
            let included = boolean(value, "include_citations").unwrap_or(!citations.is_empty());
            if !included {
                let _ = writeln!(
                    out,
                    "  Citations: {citation_count} hidden (re-read with include_citations:true)"
                );
            } else {
                render_window_heading(
                    &mut out,
                    "Citations",
                    citation_count,
                    citations.len() as i64,
                    citations_offset,
                    citations_limit,
                    "citations_offset",
                    "citations_limit",
                );
                for citation in citations {
                    let _ = writeln!(out, "    {}", inline_json(citation));
                }
            }
        }
        let comment_count = integer(item, "comment_count").unwrap_or(0);
        if comment_count > 0 {
            let comments = array(item, "comments");
            let included = boolean(value, "include_comments").unwrap_or(!comments.is_empty());
            if !included {
                let _ = writeln!(
                    out,
                    "  Comments: {comment_count} hidden (re-read with include_comments:true)"
                );
            } else {
                render_window_heading(
                    &mut out,
                    "Comments",
                    comment_count,
                    comments.len() as i64,
                    comments_offset,
                    comments_limit,
                    "comments_offset",
                    "comments_limit",
                );
                for comment in comments {
                    let body = string(comment, "body").unwrap_or_default();
                    let (preview, shortened) = one_line_preview(&body, 240);
                    let lifecycle = lifecycle_display(comment)
                        .map(|value| format!(" [{}]", display_inline(&value)))
                        .unwrap_or_default();
                    let _ = writeln!(
                        out,
                        "    {}{}  {}{}",
                        display_inline(&string(comment, "id").unwrap_or_default()),
                        lifecycle,
                        preview,
                        if shortened {
                            " (body shortened; use format:\"json\" for exact bytes)"
                        } else {
                            ""
                        },
                    );
                    if let Some(details) = exact_object_remainder(comment, &["body"]) {
                        let _ = writeln!(out, "      Comment details: {}", inline_json(&details));
                    }
                    render_comment_target(&mut out, comment, "      ");
                }
            }
        }
        for (heading, list_key, count_key) in [
            ("Links out", "links_out", "links_out_count"),
            ("Links in", "links_in", "links_in_count"),
        ] {
            let links = array(item, list_key);
            let total = integer(item, count_key).unwrap_or(0);
            if total == 0 {
                continue;
            }
            render_window_heading(
                &mut out,
                heading,
                total,
                links.len() as i64,
                links_offset,
                links_limit,
                "links_offset",
                "links_limit",
            );
            for link in links {
                let _ = writeln!(out, "    {}", inline_json(link));
            }
        }
        let ancestors = array(item, "ancestors");
        if !ancestors.is_empty() {
            let heading = match item
                .get("containment_path_visible")
                .and_then(Value::as_bool)
            {
                Some(true) => "Ancestor details (root first, complete)",
                Some(false) => {
                    "Visible ancestor details (root first; containment path incomplete or withheld)"
                }
                None => "Visible ancestor details (root first; completeness not reported)",
            };
            // Siblings share a folder, so the same ancestor block would
            // otherwise be repeated verbatim for every record in the batch.
            // Emit it once and point later records at the record that carries
            // it — a reference resolvable inside this same response, not a
            // second call, and not a silent omission.
            let mut block = String::new();
            let _ = writeln!(block, "  {heading}:");
            for ancestor in ancestors {
                let _ = writeln!(block, "    {}", inline_json(ancestor));
            }
            let record_id = display_inline(&string(item, "id").unwrap_or_default());
            match rendered_ancestors.get(&block) {
                Some(first_id) => {
                    let _ = writeln!(
                        out,
                        "  {heading}: identical to the block shown for record {first_id} above in this response.",
                    );
                }
                None => {
                    out.push_str(&block);
                    if !record_id.is_empty() {
                        rendered_ancestors.insert(block, record_id);
                    }
                }
            }
        }
        // Authored bytes come last so they cannot impersonate metadata that
        // follows them. A single-record body remains uncapped, but every line
        // is visibly quoted as untrusted record content; explicit JSON is the
        // exact-byte recovery path. Batches stay compact.
        if let Some(body) = string(item, "body") {
            if multiple {
                let (preview, changed) = one_line_preview(&body, 200);
                if changed {
                    let id = string(item, "id").unwrap_or_default();
                    let id_json = Value::String(id).to_string();
                    let _ = writeln!(
                        out,
                        "  Body preview (truncated; re-read get_record with ids:[{id_json}] \
                         or use format:\"json\" for the full verbatim body): {preview}"
                    );
                } else {
                    let _ = writeln!(out, "  Body: {preview}");
                }
            } else {
                out.push_str(
                    "  Record-authored body (untrusted; line-quoted; use format:\"json\" for exact bytes):\n",
                );
                if body.is_empty() {
                    out.push_str("    > \n");
                } else {
                    for line in body.split_inclusive('\n') {
                        let line = line.strip_suffix('\n').unwrap_or(line);
                        let line = line.strip_suffix('\r').unwrap_or(line);
                        let _ = writeln!(out, "    > {}", display_inline(line));
                    }
                }
            }
        }
    }
    if records.is_empty() {
        out.push_str("No records returned.\n");
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn render_window_heading(
    out: &mut String,
    heading: &str,
    total: i64,
    shown: i64,
    offset: i64,
    limit: i64,
    offset_arg: &str,
    limit_arg: &str,
) {
    let _ = write!(out, "  {heading} ({total} total");
    if shown > 0 {
        let _ = write!(out, ", showing {}–{}", offset + 1, offset + shown);
    } else {
        let _ = write!(out, ", showing none at {offset_arg} {offset}");
    }

    let next_offset = offset + shown;
    if next_offset < total {
        if shown == 0 && limit == 0 {
            let _ = write!(
                out,
                ", more available: set {limit_arg} above 0 and {offset_arg} to {offset}"
            );
        } else {
            let _ = write!(out, ", more available: set {offset_arg} to {next_offset}");
        }
    } else if shown == 0 && total > 0 && offset >= total {
        let _ = write!(
            out,
            ", page is past the end: set {offset_arg} between 0 and {}",
            total - 1
        );
    }
    out.push_str(")\n");
}

// ---------------------------------------------------------------------------
// query_record
// ---------------------------------------------------------------------------

fn render_query_messages(out: &mut String, value: &Value) {
    for message in array(value, "messages").iter().filter_map(Value::as_str) {
        let _ = writeln!(out, "  note: {}", display_inline(message));
    }
}

fn render_query_unknown_fields(out: &mut String, value: &Value, known: impl Fn(&str) -> bool) {
    let unknown = unknown_object_keys(value, known);
    if !unknown.is_empty() {
        let _ = writeln!(
            out,
            "Additional query fields omitted from text: {}; re-call this read with the same arguments and format:\"json\" for exact values.",
            inline_json(&json!(unknown))
        );
    }
}

fn compact_query_record_omitted_fields(record: &Value) -> Vec<String> {
    record
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(key, _)| {
            !matches!(
                key.as_str(),
                "id" | "type" | "kind" | "name" | "maturity" | "last_activity_at" | "work_state"
            )
        })
        .map(|(key, _)| key.clone())
        .collect()
}

fn render_bounded_query_json_line(
    out: &mut String,
    prefix: &str,
    value: &Value,
    remaining: &mut usize,
    recovery: &str,
) -> bool {
    if *remaining == 0 {
        return false;
    }
    let encoded = inline_json(value);
    let (preview, shortened) = one_line_preview(&encoded, (*remaining).min(1_000));
    *remaining = remaining.saturating_sub(preview.chars().count());
    let _ = writeln!(
        out,
        "{prefix}{preview}{}",
        if shortened { recovery } else { "" }
    );
    true
}

fn render_federated_query_record(value: &Value) -> String {
    let mut out = temporal_header(value);
    let complete = boolean(value, "complete").unwrap_or(false);
    let status = if complete {
        "all selected sources responded"
    } else {
        "partial source coverage"
    };
    let _ = writeln!(out, "Federated query result ({status}).");
    for (label, key) in [
        ("scope", "scope"),
        ("effective_limits", "effective_limits"),
        ("failures", "failures"),
        ("supplementary", "supplementary"),
        ("cursor_outcome", "cursor_outcome"),
    ] {
        if let Some(field) = value.get(key) {
            let _ = writeln!(out, "{label}: {}", inline_json(field));
        }
    }
    if let Some(cursor) = value.get("next_cursor") {
        if cursor.is_null() {
            out.push_str("Federated candidate window exhausted (next_cursor: null).\n");
        } else {
            let _ = writeln!(
                out,
                "Continue query_record with {}.",
                inline_json(&json!({"cursor": cursor}))
            );
        }
    }

    if string(value, "shape").as_deref() == Some("counts") {
        let buckets = array(value, "buckets");
        let _ = writeln!(
            out,
            "{} record(s) across {} federated bucket(s)",
            integer(value, "total").unwrap_or_default(),
            buckets.len()
        );
        for bucket in buckets {
            if let Some(known) = exact_known_object_remainder(bucket, &[], |key| {
                matches!(key, "key" | "count" | "source_counts")
            }) {
                let _ = writeln!(out, "  {}", inline_json(&known));
            }
            let unknown = unknown_object_keys(bucket, |key| {
                matches!(key, "key" | "count" | "source_counts")
            });
            if !unknown.is_empty() {
                let _ = writeln!(
                    out,
                    "    Additional federated bucket fields omitted from text: {}; re-call this read with the same arguments and format:\"json\" for exact values.",
                    inline_json(&json!(unknown))
                );
            }
        }
        render_query_messages(&mut out, value);
        render_query_unknown_fields(&mut out, value, |key| {
            matches!(
                key,
                "scope"
                    | "complete"
                    | "failures"
                    | "effective_limits"
                    | "supplementary"
                    | "shape"
                    | "total"
                    | "buckets"
                    | "messages"
                    | "next_cursor"
                    | "cursor_outcome"
                    | "run_context"
                    | "resolved_content_seq"
                    | "content_head_seq"
                    | "as_of"
            )
        });
        return out;
    }

    let results = array(value, "results");
    let _ = writeln!(
        out,
        "{} bounded federated candidate result(s) on this page",
        results.len()
    );
    for result in results {
        if let Some(details) = exact_known_object_remainder(result, &["record"], |key| {
            matches!(
                key,
                "ref"
                    | "provenance"
                    | "source_rank"
                    | "merge_score"
                    | "sort_tuple"
                    | "source_elapsed_ms"
                    | "source_revision"
                    | "record"
            )
        }) {
            let _ = writeln!(out, "  Federated result details: {}", inline_json(&details));
        }
        let unknown = unknown_object_keys(result, |key| {
            matches!(
                key,
                "ref"
                    | "provenance"
                    | "source_rank"
                    | "merge_score"
                    | "sort_tuple"
                    | "source_elapsed_ms"
                    | "source_revision"
                    | "record"
            )
        });
        if !unknown.is_empty() {
            let _ = writeln!(
                out,
                "  Additional federated result fields omitted from text: {}; re-call this read with the same arguments and format:\"json\" for exact values.",
                inline_json(&json!(unknown))
            );
        }
        if let Some(record) = result.get("record") {
            let _ = writeln!(out, "  record: {}", inline_json(record));
        } else {
            out.push_str("  Federated result has no record projection; use format:\"json\" for the exact result.\n");
        }
    }
    render_query_unknown_fields(&mut out, value, |key| {
        matches!(
            key,
            "scope"
                | "complete"
                | "failures"
                | "effective_limits"
                | "supplementary"
                | "results"
                | "next_cursor"
                | "cursor_outcome"
                | "run_context"
                | "resolved_content_seq"
                | "content_head_seq"
                | "as_of"
        )
    });
    out
}

fn render_query_record(value: &Value) -> String {
    let mut out = temporal_header(value);
    if value.get("scope").is_some()
        && (value.get("results").is_some() || string(value, "shape").as_deref() == Some("counts"))
    {
        return render_federated_query_record(value);
    }
    // The payload is a tagged union — counting pipelines and record pipelines
    // are different answers, and `shape` is how the payload says which.
    if string(value, "shape").as_deref() == Some("aggregate") {
        let op = value
            .get("op")
            .map(inline_json)
            .unwrap_or_else(|| "null".into());
        let facet = value
            .get("facet_key")
            .map(inline_json)
            .unwrap_or_else(|| "null".into());
        let _ = writeln!(out, "Aggregate operation: {op} · facet_key: {facet}");
        out.push_str(&render_rollup(value));
        render_query_unknown_fields(&mut out, value, |key| {
            matches!(
                key,
                "shape"
                    | "op"
                    | "facet_key"
                    | "value"
                    | "matched_records"
                    | "contributing_values"
                    | "missing_values"
                    | "non_numeric_values"
                    | "messages"
                    | "run_context"
                    | "resolved_content_seq"
                    | "content_head_seq"
                    | "as_of"
            )
        });
        return out;
    }
    if string(value, "shape").as_deref() == Some("counts") {
        let buckets = array(value, "buckets");
        let _ = writeln!(
            out,
            "{} record(s) across {} bucket(s)",
            integer(value, "total").unwrap_or_default(),
            buckets.len()
        );
        for bucket in buckets {
            let _ = writeln!(
                out,
                "  {}  {}",
                bucket
                    .get("key")
                    .map(inline_json)
                    .unwrap_or_else(|| "null".into()),
                integer(bucket, "count").unwrap_or_default(),
            );
            let unknown = unknown_object_keys(bucket, |key| matches!(key, "key" | "count"));
            if !unknown.is_empty() {
                let _ = writeln!(
                    out,
                    "    Additional count bucket fields omitted from text: {}; re-call this read with the same arguments and format:\"json\" for exact values.",
                    inline_json(&json!(unknown))
                );
            }
        }
        render_query_messages(&mut out, value);
        render_query_unknown_fields(&mut out, value, |key| {
            matches!(
                key,
                "shape"
                    | "total"
                    | "buckets"
                    | "messages"
                    | "run_context"
                    | "resolved_content_seq"
                    | "content_head_seq"
                    | "as_of"
            )
        });
        return out;
    }
    if string(value, "shape").as_deref() == Some("activity") {
        let activities = array(value, "activities");
        let total_evidence = activities
            .iter()
            .map(|item| array(item, "matches").len())
            .sum::<usize>();
        let mut shown_evidence = 0_usize;
        let mut event_detail_budget = 20_000_usize;
        let mut total_event_detail_components = 0_usize;
        let mut shown_event_detail_components = 0_usize;
        let _ = writeln!(
            out,
            "Local database: {}.",
            claimed_string(value.get("local_database_id"), "local_database_id")
        );
        let _ = writeln!(
            out,
            "{} matching event(s) through local seq {}{}",
            integer(value, "matched_event_count").unwrap_or(activities.len() as i64),
            claimed_integer(value.get("high_water_local_seq"), "high-water local seq"),
            if value.get("has_more").and_then(Value::as_bool) == Some(true) {
                " — more available via next_request"
            } else {
                ""
            }
        );
        let _ = writeln!(
            out,
            "Pinned subject membership at local seq {}.",
            claimed_integer(
                value.get("subject_as_of_local_seq"),
                "subject-as-of local seq"
            )
        );
        if let Some(next_request) = value.get("next_request") {
            if next_request.is_null() {
                out.push_str("Activity window exhausted (next_request: null).\n");
            } else {
                let _ = writeln!(out, "next_request: {}", inline_json(next_request));
            }
        }
        for item in activities {
            let event = item.get("event").unwrap_or(&Value::Null);
            if let Some(details) = exact_known_object_remainder(event, &["payload"], |key| {
                matches!(
                    key,
                    "local_seq"
                        | "id"
                        | "record_id"
                        | "type"
                        | "payload"
                        | "actor"
                        | "actor_name"
                        | "run_key"
                        | "parent_key"
                        | "intent"
                        | "created_at"
                )
            }) {
                total_event_detail_components += 1;
                shown_event_detail_components += usize::from(render_bounded_query_json_line(
                    &mut out,
                    "  Event: ",
                    &details,
                    &mut event_detail_budget,
                    " (truncated; use format:\"json\" for exact event metadata)",
                ));
            }
            if let Some(payload) = event.get("payload") {
                total_event_detail_components += 1;
                shown_event_detail_components += usize::from(render_bounded_query_json_line(
                    &mut out,
                    "    payload: ",
                    payload,
                    &mut event_detail_budget,
                    " (truncated; use format:\"json\" for the exact event payload)",
                ));
            }
            let unknown = unknown_object_keys(event, |key| {
                matches!(
                    key,
                    "local_seq"
                        | "id"
                        | "record_id"
                        | "type"
                        | "payload"
                        | "actor"
                        | "actor_name"
                        | "run_key"
                        | "parent_key"
                        | "intent"
                        | "created_at"
                )
            });
            if !unknown.is_empty() {
                let _ = writeln!(
                    out,
                    "    Additional event fields omitted from text: {}; re-call this read with the same arguments and format:\"json\" for exact values.",
                    inline_json(&json!(unknown))
                );
            }
            for evidence in array(item, "matches") {
                if shown_evidence >= 100 {
                    continue;
                }
                shown_evidence += 1;
                if let Some(known) = exact_known_object_remainder(evidence, &[], |key| {
                    matches!(
                        key,
                        "clause"
                            | "kind"
                            | "event_type"
                            | "event_families"
                            | "changed_fields"
                            | "field"
                            | "key"
                            | "before"
                            | "after"
                            | "vocab_ref"
                            | "before_vocab_ref"
                            | "after_vocab_ref"
                            | "before_terminality"
                            | "after_terminality"
                            | "change"
                            | "relationship"
                            | "direction"
                            | "source_id"
                            | "target_id"
                    )
                }) {
                    let encoded = inline_json(&known);
                    let (preview, shortened) = one_line_preview(&encoded, 1_000);
                    let _ = writeln!(
                        out,
                        "    match: {preview}{}",
                        if shortened {
                            " (truncated; use format:\"json\" for exact match evidence)"
                        } else {
                            ""
                        }
                    );
                }
                let unknown = unknown_object_keys(evidence, |key| {
                    matches!(
                        key,
                        "clause"
                            | "kind"
                            | "event_type"
                            | "event_families"
                            | "changed_fields"
                            | "field"
                            | "key"
                            | "before"
                            | "after"
                            | "vocab_ref"
                            | "before_vocab_ref"
                            | "after_vocab_ref"
                            | "before_terminality"
                            | "after_terminality"
                            | "change"
                            | "relationship"
                            | "direction"
                            | "source_id"
                            | "target_id"
                    )
                });
                if !unknown.is_empty() {
                    let _ = writeln!(
                        out,
                        "      Additional match fields omitted from text: {}; re-call this read with the same arguments and format:\"json\" for exact values.",
                        inline_json(&json!(unknown))
                    );
                }
            }
            let unknown = unknown_object_keys(item, |key| matches!(key, "event" | "matches"));
            if !unknown.is_empty() {
                let _ = writeln!(
                    out,
                    "    Additional activity-item fields omitted from text: {}; re-call this read with the same arguments and format:\"json\" for exact values.",
                    inline_json(&json!(unknown))
                );
            }
        }
        if shown_evidence < total_evidence {
            let _ = writeln!(
                out,
                "Match evidence capped: {shown_evidence} of {total_evidence} row(s) shown; use format:\"json\" for the complete page evidence."
            );
        }
        if shown_event_detail_components < total_event_detail_components {
            let _ = writeln!(
                out,
                "Event detail budget exhausted: {shown_event_detail_components} of {total_event_detail_components} metadata/payload component(s) shown; use format:\"json\" for the complete page."
            );
        }
        render_query_unknown_fields(&mut out, value, |key| {
            matches!(
                key,
                "shape"
                    | "activities"
                    | "matched_event_count"
                    | "high_water_local_seq"
                    | "subject_as_of_local_seq"
                    | "local_database_id"
                    | "has_more"
                    | "next_request"
                    | "run_context"
                    | "resolved_content_seq"
                    | "content_head_seq"
                    | "as_of"
            )
        });
        return out;
    }

    if string(value, "shape").as_deref() != Some("records") {
        let shape = value
            .get("shape")
            .map(inline_json)
            .unwrap_or_else(|| "missing".into());
        let keys = value
            .as_object()
            .into_iter()
            .flatten()
            .map(|(key, _)| key)
            .collect::<Vec<_>>();
        let _ = writeln!(
            out,
            "Unsupported query result shape {shape}; result fields {} omitted from text. Use format:\"json\" for the exact result.",
            inline_json(&json!(keys))
        );
        return out;
    }

    let Some(records) = value.get("records").and_then(Value::as_array) else {
        out.push_str(
            "Query record-page rows are missing or malformed; no empty-result inference was made; ",
        );
        out.push_str(READ_JSON_RECOVERY);
        out.push('\n');
        return out;
    };
    let (Some(total), Some(offset), Some(returned), Some(has_more)) = (
        integer(value, "total").filter(|value| *value >= 0),
        integer(value, "offset").filter(|value| *value >= 0),
        integer(value, "returned").filter(|value| *value >= 0),
        boolean(value, "has_more"),
    ) else {
        out.push_str(
            "Query record-page bounds are missing or malformed; no empty-result inference was made; ",
        );
        out.push_str(READ_JSON_RECOVERY);
        out.push('\n');
        return out;
    };
    if returned != records.len() as i64 || total < returned {
        out.push_str(
            "Query record-page counts contradict its rows; no empty-result inference was made; ",
        );
        out.push_str(READ_JSON_RECOVERY);
        out.push('\n');
        return out;
    }
    let _ = writeln!(
        out,
        "Query page: returned {returned} · offset {offset} · has_more {has_more}."
    );
    // The window is stated whenever it is one. `has_more` is the payload's own
    // flag; an agent that stops at a page it thinks is the set is the failure
    // this line exists to prevent.
    let _ = write!(out, "{total} match(es)");
    if (records.len() as i64) < total {
        if records.is_empty() {
            let _ = write!(out, " — no rows shown at offset {offset}");
            if total > 0 && offset >= total {
                let _ = write!(
                    out,
                    " (offset is past the end; set offset between 0 and {})",
                    total - 1
                );
            }
        } else {
            let _ = write!(
                out,
                " — showing {}–{}",
                offset + 1,
                offset + records.len() as i64
            );
            if value.get("has_more").and_then(Value::as_bool) == Some(true) {
                if value.get("next_request").is_some_and(Value::is_object) {
                    let _ = write!(out, ", more available via next_request");
                } else {
                    let _ = write!(
                        out,
                        ", more available; continuation unavailable for this projection"
                    );
                }
            }
        }
    }
    out.push('\n');
    if let Some(next_request) = value.get("next_request").filter(|value| !value.is_null()) {
        let _ = writeln!(out, "next_request: {}", inline_json(next_request));
    }
    if let Some(observation) = value
        .get("coordination_observation")
        .filter(|value| value.is_object())
    {
        let _ = writeln!(
            out,
            "coordination observation: {}",
            inline_json(observation)
        );
    }
    render_query_messages(&mut out, value);

    let id_width = column_width(records, |row| string(row, "id").unwrap_or_default());
    let type_width = column_width(records, type_label);
    let mut omission_signatures = std::collections::BTreeMap::<Vec<String>, usize>::new();
    for record in records {
        let omitted = compact_query_record_omitted_fields(record);
        let next_signature = omission_signatures.len() + 1;
        let signature = (!omitted.is_empty())
            .then(|| *omission_signatures.entry(omitted).or_insert(next_signature));
        let _ = writeln!(
            out,
            "{}{}",
            record_line(record, id_width, type_width),
            signature
                .map(|signature| format!("  [details D{signature}]"))
                .unwrap_or_default()
        );
        if let Some(interpretation) = record.get("interpretation") {
            render_interpretation_summary(&mut out, interpretation, "    ");
        }
        if let Some(work_state) = record.get("work_state") {
            let _ = writeln!(out, "    work: {}", inline_json(work_state));
        }
    }
    let mut omission_signatures = omission_signatures.into_iter().collect::<Vec<_>>();
    omission_signatures.sort_by_key(|(_, signature)| *signature);
    for (fields, signature) in omission_signatures {
        let _ = writeln!(
            out,
            "D{signature} fields omitted or summarized when present: {}; use format:\"json\" for exact values.",
            inline_json(&json!(fields))
        );
    }
    render_query_unknown_fields(&mut out, value, |key| {
        matches!(
            key,
            "shape"
                | "total"
                | "records"
                | "returned"
                | "has_more"
                | "offset"
                | "messages"
                | "run_context"
                | "resolved_content_seq"
                | "content_head_seq"
                | "as_of"
                | "observed_at"
                | "local_database_id"
                | "page_basis_digest"
                | "next_request"
                | "coordination_observation"
        )
    });
    out
}

fn render_rollup(value: &Value) -> String {
    let name = string(value, "rollup_name")
        .map(|name| format!("rollup `{name}`"))
        .unwrap_or_else(|| "aggregate".into());
    let scalar = value
        .get("value")
        .map(Value::to_string)
        .unwrap_or_else(|| "null".into());
    let mut out = format!(
        "{name}: {scalar} ({} matched, {} contributing, {} missing, {} non-numeric)",
        integer(value, "matched_records").unwrap_or_default(),
        integer(value, "contributing_values").unwrap_or_default(),
        integer(value, "missing_values").unwrap_or_default(),
        integer(value, "non_numeric_values").unwrap_or_default(),
    );
    if value.get("cache_hit").and_then(Value::as_bool) == Some(true) {
        out.push_str(" [cache hit]");
    }
    out.push('\n');
    render_query_messages(&mut out, value);
    out
}

// ---------------------------------------------------------------------------
// search
// ---------------------------------------------------------------------------

fn render_search(value: &Value) -> String {
    let mut out = String::new();
    let hits = array(value, "hits");
    let _ = write!(
        out,
        "{} hit(s) for {:?}",
        integer(value, "total").unwrap_or(hits.len() as i64),
        string(value, "query").unwrap_or_default(),
    );
    if let Some(scope) = string(value, "scope") {
        let _ = write!(out, " in subtree {scope}");
    }
    let limit = integer(value, "limit").unwrap_or_default();
    if value.get("limit_reached").and_then(Value::as_bool) == Some(true) {
        let _ = write!(
            out,
            " — effective limit {limit} reached; more matches may exist"
        );
    } else if limit > 0 {
        let _ = write!(out, " — effective limit {limit}");
    }
    out.push('\n');

    let id_width = column_width(hits, |hit| string(hit, "id").unwrap_or_default());
    let type_width = column_width(hits, type_label);
    for hit in hits {
        let _ = write!(
            out,
            "  {}  {}  {}  [score {}]",
            pad(&string(hit, "id").unwrap_or_default(), id_width),
            pad(&type_label(hit), type_width),
            linked_record_name(hit),
            hit.get("score")
                .and_then(Value::as_f64)
                .map(|score| score.to_string())
                .unwrap_or_else(|| "?".into()),
        );
        out.push('\n');
        // The snippet is why this hit matched — the one thing the id and name
        // cannot tell the agent.
        if let Some(snippet) = string(hit, "snippet") {
            let (flat, changed) = one_line_preview(&snippet, 200);
            if !flat.is_empty() {
                let _ = write!(out, "      {flat}");
                if changed {
                    let _ = write!(
                        out,
                        " (snippet shortened; use format:\"json\" for the full value)"
                    );
                }
                out.push('\n');
            }
        }
    }

    // Near-misses and guidance are the thin-results machinery (3bc7fd0): the
    // payload prompts reformulation because agents do not reformulate reliably
    // unprompted. Dropping either from the rendering would remove the prompt
    // from the only surface that reads it.
    let near_misses = value.get("near_misses").cloned().unwrap_or(Value::Null);
    for (label, key) in [
        ("name prefix", "name_prefix"),
        ("name infix", "name_infix"),
        ("tree siblings", "tree_siblings"),
    ] {
        let candidates = array(&near_misses, key);
        if candidates.is_empty() {
            continue;
        }
        let _ = writeln!(out, "\nNear miss — {label} ({})", candidates.len());
        for candidate in candidates {
            let _ = writeln!(
                out,
                "  {}  {}  {}",
                string(candidate, "id").unwrap_or_default(),
                type_label(candidate),
                linked_record_name(candidate),
            );
        }
    }
    if let Some(guidance) = string(value, "guidance") {
        let _ = writeln!(out, "\n{guidance}");
    }
    out
}

// ---------------------------------------------------------------------------
// Record lifecycle and history
// ---------------------------------------------------------------------------

/// `create_record` and `update_record` return the same flattened enriched
/// record as a one-id `get_record`. Reuse that rendering rather than letting
/// three presentations of one shape drift. The write handlers use the read
/// layer's default windows (200, offset 0).
fn render_enriched_write(verb: &str, value: &Value) -> String {
    let mut out = format!("{verb}\n");
    render_previous_seq(&mut out, value);
    render_write_receipt(&mut out, value);
    let mut record = value.clone();
    if let Some(object) = record.as_object_mut() {
        object.retain(|key, _| is_record_render_field(key));
        // A digest on a write is an operation receipt as well as record
        // metadata. Keep it in the receipt above without printing it twice.
        object.remove("body_digest");
    }
    out.push_str(&render_get_record(
        &json!({
            "records": [record],
            "children_limit": 200,
            "children_offset": 0,
            "links_limit": 200,
            "links_offset": 0,
        }),
        false,
    ));
    out
}

fn render_update_record(value: &Value) -> String {
    let Some(results) = value.get("results").and_then(Value::as_array) else {
        return render_enriched_write("Updated", value);
    };
    let mut out = format!(
        "Updated {} requested · {} changed · {} unchanged\n",
        claimed_integer(value.get("requested"), "requested"),
        claimed_integer(value.get("changed"), "changed"),
        claimed_integer(value.get("unchanged"), "unchanged"),
    );
    for result in results {
        let _ = writeln!(
            out,
            "  [{}] {}  {}",
            claimed_integer(result.get("index"), "index"),
            claimed_string(result.get("id"), "id"),
            claimed_string(result.get("status"), "status"),
        );
    }
    out
}

/// Preserve fields that the write handlers add around the ordinary enriched
/// record. These are receipts and warnings, not record presentation: silently
/// dropping one can hide a blocked delivery, a changed HTML validation result,
/// or artifact inputs and grants that the write could not carry forward.
///
/// Encode every value as JSON even when it is a string. Warning messages and
/// future receipt fields are handler data, and a multiline value must not be
/// able to impersonate another labelled field in the rendering.
fn render_write_receipt(out: &mut String, value: &Value) {
    let Some(object) = value.as_object() else {
        return;
    };
    let receipt = object
        .iter()
        .filter(|(key, _)| key.as_str() == "body_digest" || !is_record_render_field(key))
        .filter(|(key, _)| !matches!(key.as_str(), "previous_seq" | "run_context"))
        .collect::<Vec<_>>();
    if receipt.is_empty() {
        return;
    }
    out.push_str("Write receipt:\n");
    for (key, field) in receipt {
        let _ = writeln!(out, "  {key}: {}", inline_json(field));
    }
}

/// Fields owned by `query::read::EnrichedRecord` and its flattened
/// `RecordRow`. A new field fails safe: until it is classified here it appears
/// in the write receipt instead of being silently lost.
fn is_enriched_record_field(key: &str) -> bool {
    matches!(
        key,
        "id" | "type"
            | "kind"
            | "name"
            | "body"
            | "home_id"
            | "lifecycle_interpretation"
            | "owner_id"
            | "persistence"
            | "maturity"
            | "summary"
            | "last_activity_at"
            | "created_at"
            | "updated_at"
            | "deleted_at"
            | "federation_provenance"
            | "archived"
            | "custody_boundary"
            | "containment_path_visible"
            | "bears_shape"
            | "kind_governance"
            | "facets"
            | "links_out"
            | "links_out_count"
            | "links_in"
            | "links_in_count"
            | "children"
            | "child_count"
            | "suggestions"
            | "suggestion_count"
            | "citations"
            | "citation_count"
            | "comments"
            | "comment_count"
            | "target"
            | "contribution"
            | "ancestors"
    )
}

fn is_record_render_field(key: &str) -> bool {
    is_enriched_record_field(key)
        || matches!(
            key,
            "status"
                | "version"
                | "body_digest"
                | "has_query"
                | "query_resolution"
                | "message_expectation_state"
                | "interpretation"
                | "record_path_full"
                | "record_path"
                | "display_reference"
                | "record_url"
                | "share_url"
        )
}

fn is_get_record_response_field(key: &str) -> bool {
    matches!(
        key,
        "records"
            | "resolve"
            | "children_limit"
            | "children_offset"
            | "links_limit"
            | "links_offset"
            | "include_suggestions"
            | "suggestions_limit"
            | "suggestions_offset"
            | "include_citations"
            | "citations_limit"
            | "citations_offset"
            | "include_comments"
            | "comments_limit"
            | "comments_offset"
            | "include_interpretation"
            | "run_context"
            | "resolved_content_seq"
            | "content_head_seq"
            | "as_of"
    )
}

/// Keep the structured pre-write handle in the default text response. Without
/// this, direct handlers would return `previous_seq` only in `format:"json"`,
/// hiding the undo affordance from the default MCP path where it matters.
fn render_previous_seq(out: &mut String, value: &Value) {
    match value.get("previous_seq") {
        Some(Value::Null) => out.push_str("previous_seq: null (new record; no pre-call state)\n"),
        Some(seq) if seq.as_i64().is_some() => {
            let _ = writeln!(
                out,
                "previous_seq: {} (pass to get_record with this record id and as_of: {{content_seq: {}}} for pre-call state)",
                seq.as_i64().unwrap_or_default(),
                seq.as_i64().unwrap_or_default(),
            );
        }
        _ => {}
    }
}

fn render_delete_record(value: &Value) -> String {
    let id = string(value, "id").unwrap_or_default();
    let deleted = boolean(value, "deleted").unwrap_or(false);
    let mut out = format!(
        "{}  {}\n",
        if deleted { "Deleted" } else { "Delete result" },
        id
    );
    if let Some(at) = string(value, "deleted_at") {
        let _ = writeln!(out, "deleted_at: {at}");
    }
    render_previous_seq(&mut out, value);
    out
}

fn render_ownership_claim(value: &Value) -> String {
    let required_string = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .filter(|found| !found.trim().is_empty())
    };
    let Some((record_id, owner_id, event_id, event_seq)) = required_string("id")
        .zip(required_string("owner_id"))
        .zip(required_string("event_id"))
        .zip(
            value
                .get("event_seq")
                .and_then(Value::as_i64)
                .filter(|seq| *seq > 0),
        )
        .map(|(((record_id, owner_id), event_id), event_seq)| {
            (record_id, owner_id, event_id, event_seq)
        })
    else {
        return "Ownership-recovery receipt is missing a required mutation handle or result field; no successful claim was inferred. Exact response remains in structuredContent; do not repeat the write solely to obtain another format.\n".into();
    };
    let mut out = format!(
        "Claimed ownership  {}\nOwner: {}\nRecovery event: {} (seq {event_seq})\n",
        display_inline(record_id),
        display_inline(owner_id),
        display_inline(event_id),
    );
    render_previous_seq(&mut out, value);
    out
}

fn render_record_type_correction(value: &Value) -> String {
    let required_string = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .filter(|found| !found.trim().is_empty())
    };
    let valid_previous = value
        .get("previous_seq")
        .is_some_and(|seq| seq.is_null() || seq.as_i64().is_some());
    let Some((record_id, record_type, kind, mode, event_id, event_seq)) =
        required_string("record_id")
            .zip(required_string("type"))
            .zip(required_string("kind"))
            .zip(required_string("mode"))
            .zip(required_string("event_id"))
            .zip(
                value
                    .get("event_seq")
                    .and_then(Value::as_i64)
                    .filter(|seq| *seq > 0),
            )
            .map(
                |(((((record_id, record_type), kind), mode), event_id), event_seq)| {
                    (record_id, record_type, kind, mode, event_id, event_seq)
                },
            )
    else {
        return "Record-type correction receipt is missing a required mutation handle or result field; no successful correction was inferred. Exact response remains in structuredContent; do not repeat the write solely to obtain another format.\n".into();
    };
    if !valid_previous {
        return "Record-type correction receipt has a missing or malformed previous_seq; no successful correction was inferred. Exact response remains in structuredContent; do not repeat the write solely to obtain another format.\n".into();
    }
    let mut out = format!(
        "Corrected record type  {}  {}/{} ({})\n",
        display_inline(record_id),
        display_inline(record_type),
        display_inline(kind),
        display_inline(mode),
    );
    let _ = writeln!(
        out,
        "Correction event: {} (seq {event_seq})",
        display_inline(event_id)
    );
    if let Some(digest) = string(value, "body_digest") {
        let _ = writeln!(out, "body_digest unchanged: {digest}");
    }
    render_previous_seq(&mut out, value);
    out
}

fn render_archive_record(value: &Value) -> String {
    let archived = boolean(value, "archived").unwrap_or(false);
    let changed = boolean(value, "changed").unwrap_or(false);
    let mut out = format!(
        "{} {}  {}{}\n",
        if archived { "Archived" } else { "Restored" },
        string(value, "id").unwrap_or_default(),
        if changed {
            "changed"
        } else {
            "already in that state"
        },
        if changed { "" } else { " (no write)" },
    );
    render_previous_seq(&mut out, value);
    out
}

/// `render_record` already did the record-formatting work in its handler.
/// Return that Markdown unchanged from this function: the outer [`render`]
/// dispatcher then appends the same mandatory run-context footer used by every
/// successful text rendering. Without this prefix pass-through, text mode
/// JSON-escapes the Markdown instead of presenting it directly.
fn render_render_record(value: &Value) -> String {
    const INTERPRETATION_TEXT_BUDGET: usize = 24_000;
    let mut out = string(value, "markdown").unwrap_or_else(|| inline_json(value));
    if let Some(interpretation) = value.get("interpretation") {
        let encoded = inline_json(interpretation);
        let (preview, shortened) = one_line_preview(&encoded, INTERPRETATION_TEXT_BUDGET);
        let id = value
            .get("id")
            .map(inline_json)
            .unwrap_or_else(|| "null".into());
        let _ = writeln!(
            out,
            "\nExact interpretation projection for record {id}: {preview}"
        );
        if shortened {
            out.push_str("Interpretation projection shortened by the 24000-character text budget; re-call render_record with the same id, include_interpretation:true, and format:\"json\" for a fresh exact projection.\n");
        }
    }
    out
}

/// Guide bodies are already authored Markdown. Preserve them byte-for-byte;
/// the outer dispatcher appends the standard run-context footer.
fn render_read_guide(value: &Value) -> String {
    string(value, "markdown").unwrap_or_else(|| inline_json(value))
}

fn render_history(value: &Value) -> String {
    let events = array(value, "events");
    let order = string(value, "order").unwrap_or_else(|| "oldest_first".into());
    let detail = value
        .pointer("/representation/detail")
        .and_then(Value::as_str)
        .unwrap_or("full");
    let mut out = format!("{} event(s), {}", events.len(), order.replace('_', " "));
    if let Some(next) = integer(value, "next_after_local_seq") {
        let _ = write!(
            out,
            " — page is not exhausted; continue with after_local_seq {next}"
        );
    } else {
        out.push_str(" — stream exhausted");
    }
    out.push('\n');
    if detail == "metadata" {
        out.push_str(
            "Metadata detail: authoritative events[].payload values were omitted. Request detail \"full\" for complete caller-visible payloads. Payload sizes below are compact UTF-8 JSON bytes after authorization and redaction.\n",
        );
    }
    for event in events {
        let _ = write!(
            out,
            "\nlocal seq {}  {}  {}  {}",
            claimed_integer(event.get("local_seq"), "local seq"),
            string(event, "id").unwrap_or_default(),
            string(event, "record_id").unwrap_or_default(),
            string(event, "type").unwrap_or_default(),
        );
        if let Some(at) = string(event, "created_at") {
            let _ = write!(out, "  {at}");
        }
        out.push('\n');
        for (label, key) in [
            ("author", "actor_name"),
            ("actor", "actor"),
            ("run_key", "run_key"),
            ("parent_key", "parent_key"),
            ("intent", "intent"),
        ] {
            if let Some(found) = string(event, key) {
                let _ = writeln!(out, "  {label}: {found}");
            }
        }
        if let Some(reason) = string(event, "reason") {
            let _ = writeln!(out, "  reason: {reason}");
        }
        let changed_fields = array(event, "changed_fields")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();
        if !changed_fields.is_empty() {
            let _ = writeln!(out, "  changed fields: {}", changed_fields.join(", "));
        }
        if boolean(event, "payload_omitted") == Some(true) {
            if let Some(bytes) = integer(event, "payload_json_utf8_bytes") {
                let _ = writeln!(out, "  payload: omitted ({bytes} UTF-8 JSON bytes)");
            } else {
                out.push_str("  payload: omitted\n");
            }
        }
        if let Some(payload) = event.get("payload").filter(|value| !value.is_null()) {
            let _ = writeln!(out, "  payload: {}", inline_json(payload));
        }
    }
    out
}

fn render_whats_changed(value: &Value) -> String {
    let changes = array(value, "changes");
    let scanned = integer(value, "scanned_event_count").unwrap_or_default();
    let matched = integer(value, "matched_event_count").unwrap_or_default();
    let after = integer(value, "after_local_seq").unwrap_or_default();
    let through = integer(value, "scanned_through_local_seq").unwrap_or_default();
    let high_water = integer(value, "high_water_local_seq").unwrap_or_default();
    let mut out = format!(
        "{} change group(s) from {matched} matching event(s); {scanned} caller-visible event(s) after local seq {after} through local synchronization cursor {through} (pinned local high water {high_water})",
        changes.len()
    );
    if value.get("has_more").and_then(Value::as_bool) == Some(true) {
        if let Some(next) = integer(value, "next_after_local_seq") {
            let _ = write!(
                out,
                " — more visible matching events remain; continue with next_request (after_local_seq {next})"
            );
        }
    } else {
        out.push_str(" — window exhausted");
    }
    out.push('\n');
    if let Some(next_request) = value.get("next_request").filter(|value| !value.is_null()) {
        let _ = writeln!(out, "next_request: {}", inline_json(next_request));
    }
    for change in changes {
        let _ = write!(
            out,
            "\n{}{}  local seq {}..{}  {} event(s)",
            string(change, "record_name").unwrap_or_else(|| "(deleted or unavailable)".into()),
            string(change, "record_type")
                .map(|record_type| format!(" ({record_type})"))
                .unwrap_or_default(),
            claimed_integer(change.get("first_local_seq"), "first local seq"),
            claimed_integer(change.get("last_local_seq"), "last local seq"),
            integer(change, "event_count").unwrap_or_default(),
        );
        let _ = write!(
            out,
            "\n  record_id: {}",
            string(change, "record_id").unwrap_or_default()
        );
        if let Some(first) = string(change, "first_event_at") {
            let _ = write!(out, "\n  first event at: {first}");
        }
        if let Some(last) = string(change, "last_event_at") {
            let _ = write!(out, "\n  last event at: {last}");
        }
        for (label, key) in [
            ("author", "actor_name"),
            ("actor", "actor"),
            ("run_key", "run_key"),
        ] {
            if let Some(found) = string(change, key) {
                let _ = write!(out, "\n  {label}: {found}");
            }
        }
        for (label, key) in [
            ("types", "event_types"),
            ("families", "event_families"),
            ("fields", "changed_fields"),
        ] {
            let values = array(change, key)
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            if !values.is_empty() {
                let _ = write!(out, "\n  {label}: {}", values.join(", "));
            }
        }
        out.push('\n');
    }
    out
}

/// One exploration, its candidates, and the two things it does NOT establish.
///
/// The order claim is stated in prose because a text reader cannot see the
/// machine flag beside it, and a numbered list would silently assert exactly
/// the authored ordering v1 refuses to store.
fn render_exploration(value: &Value) -> String {
    let Some(exploration) = value.get("exploration").filter(|value| value.is_object()) else {
        return format!(
            "Exploration-create response is missing its exploration record; no outcome was inferred. Exact response: {}\n",
            inline_json(value)
        );
    };
    let Some(candidates) = value.get("candidates").and_then(Value::as_array) else {
        return format!(
            "Exploration-create response has no valid candidate list; no outcome was inferred. Exact response: {}\n",
            inline_json(value)
        );
    };
    let name = string(exploration, "name").unwrap_or_else(|| "Exploration".into());
    let mut out = format!(
        "{name} — {} candidate{} in one exploration (unordered)\n",
        candidates.len(),
        if candidates.len() == 1 { "" } else { "s" }
    );
    if let Some(id) = string(exploration, "id") {
        let _ = writeln!(out, "Exploration: {id}");
    }
    match boolean(value, "exploration_created") {
        Some(created) => {
            let _ = writeln!(out, "Exploration newly created: {created}");
        }
        None => out.push_str("Exploration creation marker is missing or malformed; no creation claim was inferred.\n"),
    }
    if let Some(role) = string(value, "selection_role") {
        let _ = writeln!(out, "Selection role: {role}");
    } else {
        out.push_str("Selection role is missing or malformed.\n");
    }
    match boolean(value, "candidate_order_is_request_order_only") {
        Some(true) => out.push_str(
            "Candidate sequence below echoes request order for input correlation only; it is not durable membership order.\n",
        ),
        Some(false) => out.push_str(
            "Candidate-order marker is false; no request-order or durable-order claim was inferred.\n",
        ),
        None => out.push_str(
            "Candidate-order marker is missing or malformed; no ordering claim was inferred.\n",
        ),
    }
    if let Some(limits) = value.get("interpretation_limits") {
        let _ = writeln!(out, "Interpretation limits: {}", inline_json(limits));
    } else {
        out.push_str("Interpretation limits are missing from the response.\n");
    }
    out.push_str(
        "These are alternatives from one exploration. Membership has no authored order, \
         and creating a candidate establishes no stance, endorsement or selection.\n",
    );
    let split_record = |record: &Value| {
        let known = record
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(key, _)| is_record_render_field(key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Map<_, _>>();
        let additional = record
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(key, _)| !is_record_render_field(key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Map<_, _>>();
        (Value::Object(known), additional)
    };
    let (exploration_record, exploration_additional) = split_record(exploration);
    let mut records = Vec::with_capacity(candidates.len() + 1);
    let mut additional_records = Vec::with_capacity(candidates.len() + 1);
    records.push(exploration_record);
    additional_records.push(("exploration", exploration_additional));
    for candidate in candidates {
        let (candidate_record, candidate_additional) = split_record(candidate);
        records.push(candidate_record);
        additional_records.push(("candidate", candidate_additional));
    }
    out.push('\n');
    out.push_str(&render_get_record(
        &json!({
            "records": records,
            "children_limit": 200,
            "children_offset": 0,
            "links_limit": 200,
            "links_offset": 0,
        }),
        false,
    ));
    for (label, additional) in additional_records {
        if !additional.is_empty() {
            let _ = writeln!(
                out,
                "Exact additional {label} fields: {}",
                inline_json(&Value::Object(additional))
            );
        }
    }
    render_fields(
        &mut out,
        value,
        &[
            "exploration",
            "exploration_created",
            "selection_role",
            "candidates",
            "candidate_order_is_request_order_only",
            "interpretation_limits",
            "run_context",
        ],
    );
    out
}

/// The moment around one event. Every hedge in the projection survives into
/// the prose: opened is not comprehension, and unavailable is not empty.
fn render_event_context(value: &Value) -> String {
    const CONTROL_BUDGET: usize = 4_000;
    const CONSULTED_BUDGET: usize = 4_000;
    const LIMITS_BUDGET: usize = 2_000;
    const EVENT_PAYLOAD_BUDGET: usize = 3_000;
    const BEFORE_BODY_BUDGET: usize = 4_000;
    const AFTER_BODY_BUDGET: usize = 4_000;
    const NEIGHBOUR_BUDGET: usize = 5_000;
    const COMPONENT_CAP: usize = 2_000;

    let Some(_) = value.as_object() else {
        return format!(
            "Event context is malformed and was not interpreted; {READ_JSON_RECOVERY}\n"
        );
    };
    let mut out = "Event context.\n".to_string();
    let mut control_remaining = CONTROL_BUDGET;
    let mut consulted_remaining = CONSULTED_BUDGET;
    let mut limits_remaining = LIMITS_BUDGET;

    let event = value.get("event");
    if let Some(event) = event.filter(|event| event.is_object()) {
        let (metadata, malformed) = typed_context_projection(
            event,
            |key| {
                matches!(
                    key,
                    "seq"
                        | "id"
                        | "record_id"
                        | "type"
                        | "payload"
                        | "actor"
                        | "actor_name"
                        | "run_key"
                        | "parent_key"
                        | "intent"
                        | "created_at"
                )
            },
            |key, field| match key {
                "seq" => field.as_i64().is_some() || field.as_u64().is_some(),
                "payload" => true,
                _ => string_or_null(field),
            },
        );
        let metadata = exact_object_remainder(&metadata, &["payload"]).unwrap_or_else(|| json!({}));
        render_bounded_context_component(
            &mut out,
            "Selected event: ",
            &metadata,
            &mut control_remaining,
            COMPONENT_CAP,
        );
        render_context_malformed_fields(
            &mut out,
            "selected event",
            malformed,
            &mut control_remaining,
        );
        render_context_unknowns(
            &mut out,
            "selected event",
            event,
            |key| {
                matches!(
                    key,
                    "seq"
                        | "id"
                        | "record_id"
                        | "type"
                        | "payload"
                        | "actor"
                        | "actor_name"
                        | "run_key"
                        | "parent_key"
                        | "intent"
                        | "created_at"
                )
            },
            &mut control_remaining,
        );
    } else {
        out.push_str("Selected event: missing or malformed; ");
        out.push_str(READ_JSON_RECOVERY);
        out.push('\n');
    }

    match value.get("run") {
        Some(Value::Null) => out.push_str("Run correlation: absent.\n"),
        Some(run) if run.is_object() => {
            let (projection, malformed) = typed_context_projection(
                run,
                |key| matches!(key, "run_key" | "agent_key" | "assurance"),
                |_, field| string_or_null(field),
            );
            render_bounded_context_component(
                &mut out,
                "Run correlation (not persistent identity): ",
                &projection,
                &mut control_remaining,
                COMPONENT_CAP,
            );
            render_context_malformed_fields(
                &mut out,
                "run correlation",
                malformed,
                &mut control_remaining,
            );
            render_context_unknowns(
                &mut out,
                "run correlation",
                run,
                |key| matches!(key, "run_key" | "agent_key" | "assurance"),
                &mut control_remaining,
            );
        }
        _ => {
            out.push_str("Run correlation: missing or malformed; ");
            out.push_str(READ_JSON_RECOVERY);
            out.push('\n');
        }
    }
    match value.get("intent_at_event") {
        Some(Value::Null) => out.push_str("Intent in force at this event: not declared.\n"),
        Some(Value::String(intent)) => {
            render_bounded_context_component(
                &mut out,
                "Intent in force at this event: ",
                &json!(intent),
                &mut control_remaining,
                COMPONENT_CAP,
            );
        }
        _ => {
            out.push_str("Intent in force at this event: missing or malformed; ");
            out.push_str(READ_JSON_RECOVERY);
            out.push('\n');
        }
    }

    match value.get("delta") {
        Some(delta) if delta.is_object() => {
            let (metadata, malformed) = typed_context_projection(
                delta,
                |key| {
                    matches!(
                        key,
                        "kind"
                            | "event_type"
                            | "record_id"
                            | "before_event_id"
                            | "before"
                            | "after"
                            | "is_creation"
                    )
                },
                |key, field| match key {
                    "is_creation" => field.is_boolean(),
                    _ => string_or_null(field),
                },
            );
            let metadata = exact_object_remainder(&metadata, &["before", "after"])
                .unwrap_or_else(|| json!({}));
            render_bounded_context_component(
                &mut out,
                "Delta details: ",
                &metadata,
                &mut control_remaining,
                COMPONENT_CAP,
            );
            render_context_malformed_fields(&mut out, "delta", malformed, &mut control_remaining);
            render_context_unknowns(
                &mut out,
                "delta",
                delta,
                |key| {
                    matches!(
                        key,
                        "kind"
                            | "event_type"
                            | "record_id"
                            | "before_event_id"
                            | "before"
                            | "after"
                            | "is_creation"
                    )
                },
                &mut control_remaining,
            );
        }
        _ => {
            out.push_str("Delta: missing or malformed; ");
            out.push_str(READ_JSON_RECOVERY);
            out.push('\n');
        }
    }

    // Consulted evidence and interpretation limits are coordination controls,
    // so render them before bulk event bodies and neighbouring payloads.
    match value.get("consulted") {
        Some(consulted) if consulted.is_object() => {
            let status = consulted.get("status").and_then(Value::as_str);
            let records = consulted.get("records").and_then(Value::as_array);
            match (status, records) {
                (Some("unavailable"), Some(_)) => out.push_str(
                    "Opened before this event: context unavailable. The read log is best-effort operational evidence, so this is NOT a statement that no records were opened.\n",
                ),
                (Some(status @ ("available" | "partial")), Some(records)) => {
                    match consulted.get("limit").and_then(Value::as_u64) {
                        Some(limit) => {
                            let _ = writeln!(out, "Opened before this event: {status}; {} visible record(s) returned from a bounded window of at most {limit}.", records.len());
                        }
                        None => out.push_str("Opened before this event: limit is missing or malformed; the visible returned page is not treated as an exhaustive window.\n"),
                    }
                    if records.is_empty() && status == "available" {
                        out.push_str("  no visible qualifying opens were returned in the bounded scope\n");
                    }
                    let mut rendered = 0usize;
                    let mut malformed = 0usize;
                    for record in records {
                        if !record.is_object() {
                            malformed += 1;
                            continue;
                        }
                        let (projection, malformed_fields) = typed_context_projection(record, |key| {
                            matches!(key, "record_id" | "name" | "type" | "kind" | "last_opened_at" | "interaction" | "is_event_target")
                        }, |key, field| match key {
                            "is_event_target" => field.is_boolean(),
                            _ => string_or_null(field),
                        });
                        if render_bounded_context_component(
                            &mut out,
                            "  - ",
                            &projection,
                            &mut consulted_remaining,
                            750,
                        ) {
                            rendered += 1;
                        }
                        render_context_malformed_fields(&mut out, "consulted record", malformed_fields, &mut consulted_remaining);
                        if consulted_remaining > 0 {
                            render_context_unknowns(&mut out, "consulted record", record, |key| {
                                matches!(key, "record_id" | "name" | "type" | "kind" | "last_opened_at" | "interaction" | "is_event_target")
                            }, &mut consulted_remaining);
                        }
                    }
                    if rendered + malformed < records.len() || malformed > 0 {
                        let _ = writeln!(out, "Consulted-record detail: {rendered} rendered, {malformed} malformed, {} omitted by the text budget; {READ_JSON_RECOVERY}", records.len().saturating_sub(rendered + malformed));
                    }
                    if let Some(surfaced) = consulted.get("other_records_surfaced").and_then(Value::as_u64) {
                        let _ = writeln!(out, "Other visible records merely surfaced: {surfaced} (weaker, visibility-filtered evidence; not consulted).");
                    } else {
                        out.push_str("Other-record surfaced count: missing or malformed; no absence is inferred.\n");
                    }
                }
                _ => out.push_str(
                    "Opened before this event: status or records are missing/malformed; no absence is inferred. Re-call this read with the same arguments and format:\"json\" for a fresh exact JSON projection.\n",
                ),
            }
            render_context_unknowns(
                &mut out,
                "consulted evidence",
                consulted,
                |key| {
                    matches!(
                        key,
                        "label" | "status" | "records" | "other_records_surfaced" | "limit"
                    )
                },
                &mut consulted_remaining,
            );
        }
        _ => {
            out.push_str("Opened before this event: evidence envelope missing or malformed; no absence is inferred. ");
            out.push_str(READ_JSON_RECOVERY);
            out.push('\n');
        }
    }

    match value.get("interpretation_limits") {
        Some(Value::Array(limits)) => {
            let mut valid = Vec::new();
            let mut malformed = Vec::new();
            for (index, limit) in limits.iter().enumerate() {
                if limit.is_string() {
                    valid.push(limit.clone());
                } else {
                    malformed.push(index);
                }
            }
            render_bounded_context_component(
                &mut out,
                "Interpretation limits: ",
                &Value::Array(valid),
                &mut limits_remaining,
                COMPONENT_CAP,
            );
            if !malformed.is_empty() {
                render_bounded_context_component(
                    &mut out,
                    "Malformed interpretation-limit indexes omitted without interpretation: ",
                    &json!(malformed),
                    &mut limits_remaining,
                    500,
                );
                out.push_str(READ_JSON_RECOVERY);
                out.push('\n');
            }
        }
        _ => {
            out.push_str("Interpretation limits: missing or malformed; ");
            out.push_str(READ_JSON_RECOVERY);
            out.push('\n');
        }
    }

    let mut payload_remaining = EVENT_PAYLOAD_BUDGET;
    if let Some(payload) = event
        .and_then(|event| event.get("payload"))
        .filter(|payload| !payload.is_null())
    {
        render_bounded_context_component(
            &mut out,
            "Selected event payload: ",
            payload,
            &mut payload_remaining,
            EVENT_PAYLOAD_BUDGET,
        );
    }
    if let Some(delta) = value.get("delta").filter(|delta| delta.is_object()) {
        let mut before_remaining = BEFORE_BODY_BUDGET;
        let mut after_remaining = AFTER_BODY_BUDGET;
        if let Some(body @ (Value::String(_) | Value::Null)) = delta.get("before") {
            render_bounded_context_component(
                &mut out,
                "Before body: ",
                body,
                &mut before_remaining,
                BEFORE_BODY_BUDGET,
            );
        }
        if let Some(body @ (Value::String(_) | Value::Null)) = delta.get("after") {
            render_bounded_context_component(
                &mut out,
                "After body: ",
                body,
                &mut after_remaining,
                AFTER_BODY_BUDGET,
            );
        }
    }

    let mut neighbour_remaining = NEIGHBOUR_BUDGET;
    match value.get("neighbouring_events") {
        Some(Value::Array(events)) => {
            let _ = writeln!(out, "Neighbouring events returned: {}.", events.len());
            let mut rendered = 0usize;
            let mut malformed = 0usize;
            for event in events {
                if !event.is_object() {
                    malformed += 1;
                    continue;
                }
                let (projection, malformed_fields) = typed_context_projection(
                    event,
                    |key| {
                        matches!(
                            key,
                            "seq"
                                | "id"
                                | "record_id"
                                | "type"
                                | "payload"
                                | "actor"
                                | "actor_name"
                                | "run_key"
                                | "parent_key"
                                | "intent"
                                | "created_at"
                        )
                    },
                    |key, field| match key {
                        "seq" => field.as_i64().is_some() || field.as_u64().is_some(),
                        "payload" => true,
                        _ => string_or_null(field),
                    },
                );
                if render_bounded_context_component(
                    &mut out,
                    "- ",
                    &projection,
                    &mut neighbour_remaining,
                    COMPONENT_CAP,
                ) {
                    rendered += 1;
                }
                render_context_malformed_fields(
                    &mut out,
                    "neighbouring event",
                    malformed_fields,
                    &mut neighbour_remaining,
                );
                if neighbour_remaining > 0 {
                    render_context_unknowns(
                        &mut out,
                        "neighbouring event",
                        event,
                        |key| {
                            matches!(
                                key,
                                "seq"
                                    | "id"
                                    | "record_id"
                                    | "type"
                                    | "payload"
                                    | "actor"
                                    | "actor_name"
                                    | "run_key"
                                    | "parent_key"
                                    | "intent"
                                    | "created_at"
                            )
                        },
                        &mut neighbour_remaining,
                    );
                }
            }
            if rendered + malformed < events.len() || malformed > 0 {
                let _ = writeln!(out, "Neighbouring event detail: {rendered} rendered, {malformed} malformed, {} omitted by the text budget; {READ_JSON_RECOVERY}", events.len().saturating_sub(rendered + malformed));
            }
        }
        _ => {
            out.push_str("Neighbouring events: missing or malformed; ");
            out.push_str(READ_JSON_RECOVERY);
            out.push('\n');
        }
    }
    render_context_unknowns(
        &mut out,
        "event context",
        value,
        |key| {
            matches!(
                key,
                "event"
                    | "run"
                    | "intent_at_event"
                    | "delta"
                    | "neighbouring_events"
                    | "consulted"
                    | "interpretation_limits"
                    | "run_context"
            )
        },
        &mut control_remaining,
    );
    if control_remaining == 0
        || consulted_remaining == 0
        || limits_remaining == 0
        || payload_remaining == 0
        || neighbour_remaining == 0
    {
        out.push_str("Event-context detail budget exhausted; ");
        out.push_str(READ_JSON_RECOVERY);
        out.push('\n');
    }
    out.push_str("Opening a record establishes no comprehension, reliance or agreement.\n");
    out
}

fn render_run_activity(value: &Value) -> String {
    const DETAIL_BUDGET: usize = 24_000;
    let Some(_) = value.as_object() else {
        return format!(
            "Run activity is malformed and was not interpreted; {READ_JSON_RECOVERY}\n"
        );
    };
    if value.get("mode").and_then(Value::as_str) == Some("discovery") {
        return render_run_discovery(value, DETAIL_BUDGET);
    }
    let for_run = value.get("for_run").and_then(Value::as_str);
    let include_children = value.get("include_child_runs").and_then(Value::as_bool);
    let mut out = match (for_run, include_children) {
        (Some(run), Some(children)) => {
            let encoded = inline_json(&json!(run));
            let (preview, shortened) = one_line_preview(&encoded, 500);
            format!(
                "Run activity scope: for_run={preview}{} · include_child_runs={children}.\n",
                if shortened {
                    " (shortened; re-call with the same arguments and format:\"json\" for a fresh exact JSON projection)"
                } else {
                    ""
                }
            )
        }
        _ => "Run activity scope is missing or malformed; no empty-result inference is made.\n"
            .into(),
    };
    let scope_valid = for_run.is_some() && include_children.is_some();
    let availability = value.get("availability").filter(|item| item.is_object());
    let (validated_availability, malformed_availability) = availability
        .map(|item| {
            typed_context_projection(
                item,
                |key| matches!(key, "status" | "reason" | "visibility_filtered"),
                |key, field| match key {
                    "status" => field.is_string(),
                    "reason" => string_or_null(field),
                    "visibility_filtered" => field.is_boolean() || field.is_null(),
                    _ => false,
                },
            )
        })
        .unwrap_or_else(|| (json!({}), Vec::new()));
    let status = validated_availability.get("status").and_then(Value::as_str);
    let visibility_filtered = validated_availability
        .get("visibility_filtered")
        .and_then(Value::as_bool);
    let mut remaining = DETAIL_BUDGET;
    render_context_malformed_fields(
        &mut out,
        "availability",
        malformed_availability,
        &mut remaining,
    );
    match status {
        Some("unavailable") => {
            out.push_str("Aggregate read activity is unavailable; this is NOT evidence that no activity occurred.\n");
            match validated_availability.get("reason") {
                Some(reason @ (Value::String(_) | Value::Null)) => {
                    render_bounded_context_component(
                        &mut out,
                        "Unavailable reason: ",
                        reason,
                        &mut remaining,
                        500,
                    );
                }
                _ => out.push_str("Unavailable reason is missing or malformed.\n"),
            }
        }
        Some("available") => match value.get("read_activity") {
            Some(Value::Array(rows)) => {
                if validated_availability
                    .get("reason")
                    .is_some_and(|reason| !reason.is_null())
                {
                    out.push_str("Availability reason was present for available status and was not interpreted; re-call with the same arguments and format:\"json\" for a fresh exact JSON projection.\n");
                }
                let _ = writeln!(out, "Visible aggregate read activity: {} run row(s) returned; interaction counts are visibility-filtered.", rows.len());
                if rows.is_empty() && scope_valid {
                    match visibility_filtered {
                        Some(true) => out.push_str("No visible aggregate read-activity rows were returned; hidden activity may exist.\n"),
                        Some(false) => out.push_str("No visible aggregate read-activity rows were returned in this available scope.\n"),
                        None => out.push_str("No visible aggregate read-activity rows were returned, but visibility coverage is missing or malformed; no exhaustive absence is inferred.\n"),
                    }
                }
                let mut rendered = 0usize;
                let mut malformed = 0usize;
                for row in rows {
                    if !row.is_object() {
                        malformed += 1;
                        continue;
                    }
                    let (projection, malformed_fields) = typed_context_projection(
                        row,
                        |key| {
                            matches!(
                                key,
                                "run_key"
                                    | "parent_key"
                                    | "searches"
                                    | "surfaced"
                                    | "opened"
                                    | "mutated"
                            )
                        },
                        |key, field| match key {
                            "run_key" => field.is_string(),
                            "parent_key" => string_or_null(field),
                            _ => field.as_i64().is_some() || field.as_u64().is_some(),
                        },
                    );
                    if render_bounded_context_component(
                        &mut out,
                        "- ",
                        &projection,
                        &mut remaining,
                        1_000,
                    ) {
                        rendered += 1;
                    }
                    render_context_malformed_fields(
                        &mut out,
                        "activity row",
                        malformed_fields,
                        &mut remaining,
                    );
                    if remaining > 0 {
                        render_context_unknowns(
                            &mut out,
                            "activity row",
                            row,
                            |key| {
                                matches!(
                                    key,
                                    "run_key"
                                        | "parent_key"
                                        | "searches"
                                        | "surfaced"
                                        | "opened"
                                        | "mutated"
                                )
                            },
                            &mut remaining,
                        );
                    }
                }
                if rendered + malformed < rows.len() || malformed > 0 {
                    let _ = writeln!(
                        out,
                        "Run activity detail: {rendered} rendered, {malformed} malformed, {} omitted by the text budget; {READ_JSON_RECOVERY}",
                        rows.len().saturating_sub(rendered + malformed)
                    );
                }
            }
            _ => {
                out.push_str("Read-activity rows are missing or malformed; no empty-result inference is made. ");
                out.push_str(READ_JSON_RECOVERY);
                out.push('\n');
            }
        },
        _ => {
            out.push_str("Run-activity availability is missing, malformed, or unsupported; no empty-result inference is made. ");
            out.push_str(READ_JSON_RECOVERY);
            out.push('\n');
        }
    }
    if let Some(availability) = availability {
        render_context_unknowns(
            &mut out,
            "availability",
            availability,
            |key| matches!(key, "status" | "reason" | "visibility_filtered"),
            &mut remaining,
        );
    }
    if remaining == 0 {
        out.push_str("Run-activity text detail budget reached its limit; ");
        out.push_str(READ_JSON_RECOVERY);
        out.push('\n');
    }
    render_context_unknowns(
        &mut out,
        "run activity",
        value,
        |key| {
            matches!(
                key,
                "for_run" | "include_child_runs" | "availability" | "read_activity" | "run_context"
            )
        },
        &mut remaining,
    );
    out
}

fn render_run_discovery(value: &Value, detail_budget: usize) -> String {
    let observed_at = claimed_string(value.get("observed_at"), "observed_at");
    let Some(runs) = value.get("runs").and_then(Value::as_array) else {
        return format!(
            "Own-account run discovery observed at {observed_at}.\n\
             Run-discovery rows are missing or malformed; no empty-result inference was made; \
             {READ_JSON_RECOVERY}\n"
        );
    };
    let mut out = format!(
        "Own-account run discovery observed at {observed_at}: {} run(s) returned.\n",
        runs.len()
    );
    if runs.is_empty() {
        out.push_str("No open or recently closed runs were returned for this account in the bounded observation.\n");
    }
    let mut remaining = detail_budget;
    for run in runs {
        render_bounded_context_component(&mut out, "- ", run, &mut remaining, 1_500);
    }
    match boolean(value, "has_more") {
        Some(true) if value.get("next_cursor").is_some_and(Value::is_object) => {
            out.push_str("More own-account runs are available; pass next_cursor back as cursor to continue the same observation.\n");
        }
        Some(true) => out.push_str(
            "More own-account runs may be available, but the continuation is missing or malformed.\n",
        ),
        Some(false) => out.push_str("Run discovery is complete for this bounded observation.\n"),
        None => out.push_str("Run-discovery completeness is missing or malformed.\n"),
    }
    if remaining == 0 {
        out.push_str("Run-discovery text detail budget reached its limit; ");
        out.push_str(READ_JSON_RECOVERY);
        out.push('\n');
    }
    out
}

fn render_bounded_context_component(
    out: &mut String,
    prefix: &str,
    value: &Value,
    remaining: &mut usize,
    component_cap: usize,
) -> bool {
    if *remaining == 0 {
        return false;
    }
    let encoded = inline_json(value);
    let cap = (*remaining).min(component_cap);
    let (preview, shortened) = one_line_preview(&encoded, cap);
    *remaining = remaining.saturating_sub(preview.chars().count());
    let _ = writeln!(
        out,
        "{prefix}{preview}{}",
        if shortened {
            READ_JSON_SHORTENED_RECOVERY
        } else {
            ""
        }
    );
    true
}

fn render_context_unknowns(
    out: &mut String,
    label: &str,
    value: &Value,
    known: impl Fn(&str) -> bool,
    remaining: &mut usize,
) {
    let unknown = unknown_object_keys(value, known);
    if unknown.is_empty() {
        return;
    }
    if render_bounded_context_component(
        out,
        &format!("Additional {label} fields omitted from text: "),
        &json!(unknown),
        remaining,
        1_000,
    ) {
        out.push_str(READ_JSON_RECOVERY);
        out.push('\n');
    }
}

fn typed_context_projection(
    value: &Value,
    known: impl Fn(&str) -> bool,
    valid: impl Fn(&str, &Value) -> bool,
) -> (Value, Vec<String>) {
    let mut projection = Map::new();
    let mut malformed = Vec::new();
    for (key, field) in value.as_object().into_iter().flatten() {
        if !known(key) {
            continue;
        }
        if valid(key, field) {
            projection.insert(key.clone(), field.clone());
        } else {
            malformed.push(key.clone());
        }
    }
    (Value::Object(projection), malformed)
}

fn render_context_malformed_fields(
    out: &mut String,
    label: &str,
    malformed: Vec<String>,
    remaining: &mut usize,
) {
    if malformed.is_empty() {
        return;
    }
    if render_bounded_context_component(
        out,
        &format!("Malformed {label} fields omitted without interpretation: "),
        &json!(malformed),
        remaining,
        1_000,
    ) {
        out.push_str(READ_JSON_RECOVERY);
        out.push('\n');
    }
}

fn string_or_null(value: &Value) -> bool {
    value.is_string() || value.is_null()
}

// ---------------------------------------------------------------------------
// Links and facets
// ---------------------------------------------------------------------------

fn render_manage_links(value: &Value) -> String {
    let Some(action) = value.get("action").and_then(Value::as_str) else {
        return format!(
            "Link response has no valid server-authored action and was not interpreted; {MANAGE_LINKS_WRITE_RECOVERY}\n"
        );
    };
    match action {
        "add" | "remove" => render_manage_links_write(value, action),
        "list" => render_manage_links_list(value),
        _ => format!(
            "Link action {} is unsupported and no outcome was inferred; {MANAGE_LINKS_WRITE_RECOVERY}\n",
            inline_json(&json!(action))
        ),
    }
}

const MANAGE_LINKS_TEXT_BUDGET: usize = 20_000;
const MANAGE_LINKS_ROW_LIMIT: usize = 200;
const MANAGE_LINKS_WRITE_RECOVERY: &str = "Exact response remains in structuredContent; do not repeat a possibly non-idempotent write solely to obtain another format. For a future write, request format:\"json\" on the original call.";

fn link_nonblank(value: &Value) -> bool {
    value.as_str().is_some_and(|text| !text.trim().is_empty())
}

fn link_nonempty_token(value: &Value) -> bool {
    value.as_str().is_some_and(|text| !text.is_empty())
}

fn link_positive_seq(value: &Value) -> bool {
    value.as_i64().is_some_and(|seq| seq > 0)
}

fn link_render_unknowns(
    out: &mut String,
    label: &str,
    value: &Value,
    known: impl Fn(&str) -> bool,
    remaining: &mut usize,
) {
    render_context_unknowns(out, label, value, known, remaining);
}

fn link_write_bounded_component(
    out: &mut String,
    prefix: &str,
    value: &Value,
    remaining: &mut usize,
    component_cap: usize,
) -> bool {
    if *remaining == 0 {
        return false;
    }
    let encoded = inline_json(value);
    let (preview, shortened) = one_line_preview(&encoded, (*remaining).min(component_cap));
    *remaining = remaining.saturating_sub(preview.chars().count());
    let _ = writeln!(
        out,
        "{prefix}{preview}{}",
        if shortened {
            format!(" (shortened; {MANAGE_LINKS_WRITE_RECOVERY})")
        } else {
            String::new()
        }
    );
    true
}

fn link_write_unknowns(
    out: &mut String,
    label: &str,
    value: &Value,
    known: impl Fn(&str) -> bool,
    remaining: &mut usize,
) {
    let unknown = unknown_object_keys(value, known);
    if !unknown.is_empty()
        && link_write_bounded_component(
            out,
            &format!("Additional {label} fields omitted from text: "),
            &json!(unknown),
            remaining,
            1_000,
        )
    {
        let _ = writeln!(out, "{MANAGE_LINKS_WRITE_RECOVERY}");
    }
}

fn render_manage_links_write(value: &Value, action: &str) -> String {
    let expected_status = if action == "add" { "added" } else { "removed" };
    let expected_event_type = if action == "add" {
        "link.added"
    } else {
        "link.removed"
    };
    let source = value.get("source_id");
    let target = value.get("target_id");
    let relationship = value.get("relationship");
    let previous_seq = value.get("previous_seq");
    let Some(receipt) = value.get("write_receipt").and_then(Value::as_object) else {
        return format!(
            "Link {action} response has no valid write receipt and no write outcome was inferred; {MANAGE_LINKS_WRITE_RECOVERY}\n"
        );
    };
    if value.get("format").and_then(Value::as_str) != Some("native.manage-links-write.v1")
        || value.get("status").and_then(Value::as_str) != Some(expected_status)
        || !source.is_some_and(link_nonblank)
        || !target.is_some_and(link_nonblank)
        || !relationship.is_some_and(link_nonblank)
        || !previous_seq.is_some_and(link_positive_seq)
    {
        return format!(
            "Link {action} response is malformed and no write outcome was inferred; {MANAGE_LINKS_WRITE_RECOVERY}\n"
        );
    }

    let kind = receipt.get("kind").and_then(Value::as_str);
    let receipt_valid = match kind {
        Some("content_event") => receipt.get("event").is_some_and(|event| {
            event.is_object()
                && ["event_id", "record_id", "event_type", "created_at"]
                    .into_iter()
                    .all(|key| event.get(key).is_some_and(link_nonblank))
                && event.get("seq").and_then(Value::as_i64).is_some_and(|seq| {
                    seq > 0
                        && previous_seq
                            .and_then(Value::as_i64)
                            .is_none_or(|previous| seq > previous)
                })
                && event.get("record_id") == source
                && event.get("event_type").and_then(Value::as_str) == Some(expected_event_type)
        }),
        Some("relationship_assertion") => {
            let origin = receipt.get("relationship_origin_db_id");
            let outputs = receipt.get("output_events").and_then(Value::as_array);
            [
                "relationship_origin_db_id",
                "relationship_id",
                "assertion_id",
                "action_attestation_id",
            ]
            .into_iter()
            .all(|key| receipt.get(key).is_some_and(link_nonblank))
                && outputs.is_some_and(|events| {
                    !events.is_empty()
                        && events.len() <= 2
                        && events.iter().all(|event| {
                            event.is_object()
                                && event.get("domain").and_then(Value::as_str)
                                    == Some("relationship")
                                && event.get("issuer_origin_db_id").is_some_and(link_nonblank)
                                && event.get("issuer_origin_db_id") == origin
                                && event.get("event_id").is_some_and(link_nonblank)
                        })
                })
                && [
                    "relationship_origin_db_id",
                    "relationship_id",
                    "assertion_id",
                    "action_attestation_id",
                    "output_events",
                ]
                .into_iter()
                .all(|key| value.get(key).is_some() && value.get(key) == receipt.get(key))
        }
        _ => false,
    };
    if !receipt_valid {
        return format!(
            "Link {action} write receipt is malformed and no write outcome was inferred; {MANAGE_LINKS_WRITE_RECOVERY}\n"
        );
    }

    let mut out = format!(
        "Link {action} write committed via {}.\n",
        inline_json(receipt.get("kind").unwrap())
    );
    let mut remaining = MANAGE_LINKS_TEXT_BUDGET.saturating_sub(out.chars().count());
    link_write_bounded_component(
        &mut out,
        "Link coordinates: ",
        &json!({"source_id":source,"relationship":relationship,"target_id":target,"status":expected_status}),
        &mut remaining,
        2_000,
    );
    match kind {
        Some("content_event") => {
            let event = receipt.get("event").unwrap();
            link_write_bounded_component(
                &mut out,
                "Committed content event: ",
                &json!({
                    "seq":event["seq"],
                    "event_id":event["event_id"],
                    "record_id":event["record_id"],
                    "event_type":event["event_type"],
                    "created_at":event["created_at"],
                }),
                &mut remaining,
                3_000,
            );
            link_write_unknowns(
                &mut out,
                "content-event receipt",
                event,
                |key| {
                    matches!(
                        key,
                        "seq" | "event_id" | "record_id" | "event_type" | "created_at"
                    )
                },
                &mut remaining,
            );
        }
        Some("relationship_assertion") => {
            let projected_outputs = receipt["output_events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|event| {
                    json!({
                        "domain":event["domain"],
                        "issuer_origin_db_id":event["issuer_origin_db_id"],
                        "event_id":event["event_id"],
                    })
                })
                .collect::<Vec<_>>();
            link_write_bounded_component(
                &mut out,
                "Relationship assertion receipt: ",
                &json!({
                    "relationship_origin_db_id":receipt["relationship_origin_db_id"],
                    "relationship_id":receipt["relationship_id"],
                    "assertion_id":receipt["assertion_id"],
                    "action_attestation_id":receipt["action_attestation_id"],
                    "output_events":projected_outputs,
                }),
                &mut remaining,
                6_000,
            );
            for event in receipt["output_events"].as_array().unwrap() {
                link_write_unknowns(
                    &mut out,
                    "relationship output-event",
                    event,
                    |key| matches!(key, "domain" | "issuer_origin_db_id" | "event_id"),
                    &mut remaining,
                );
            }
        }
        _ => unreachable!("receipt kind was validated"),
    }
    render_previous_seq(&mut out, value);
    link_write_unknowns(
        &mut out,
        "link write-receipt",
        &Value::Object(receipt.clone()),
        |key| {
            matches!(
                key,
                "kind"
                    | "event"
                    | "relationship_origin_db_id"
                    | "relationship_id"
                    | "assertion_id"
                    | "action_attestation_id"
                    | "output_events"
            )
        },
        &mut remaining,
    );
    link_write_unknowns(
        &mut out,
        "manage-links write",
        value,
        |key| {
            matches!(
                key,
                "action"
                    | "format"
                    | "status"
                    | "source_id"
                    | "target_id"
                    | "relationship"
                    | "previous_seq"
                    | "write_receipt"
                    | "relationship_origin_db_id"
                    | "relationship_id"
                    | "assertion_id"
                    | "action_attestation_id"
                    | "output_events"
                    | "run_context"
            )
        },
        &mut remaining,
    );
    out
}

fn link_row_valid(link: &Value, direction: &str, record_id: &Value) -> bool {
    link.is_object()
        && ["id", "source_id", "target_id", "created_at"]
            .into_iter()
            .all(|key| link.get(key).is_some_and(link_nonblank))
        && link.get("relationship").is_some_and(link_nonempty_token)
        && link
            .get("note")
            .is_some_and(|note| note.is_null() || note.is_string())
        && if direction == "out" {
            link.get("source_id") == Some(record_id)
        } else {
            link.get("target_id") == Some(record_id)
        }
}

fn render_manage_links_list(value: &Value) -> String {
    let record_id = value.get("record_id");
    let outgoing = value.get("links_out").and_then(Value::as_array);
    let incoming = value.get("links_in").and_then(Value::as_array);
    let limit = value.get("limit").and_then(Value::as_u64);
    let returned = value.get("returned").and_then(Value::as_u64);
    let has_more = value.get("has_more").and_then(Value::as_bool);
    let next_cursor = value.get("next_cursor");
    let next_call = value.get("next_call");
    let cursor_valid = value
        .get("cursor")
        .is_some_and(|cursor| cursor.is_null() || link_nonblank(cursor));
    let continuation_valid = match has_more {
        Some(true) => {
            next_cursor.is_some_and(link_nonblank)
                && next_call.is_some_and(|call| {
                    call.get("action").and_then(Value::as_str) == Some("list")
                        && call.get("record_id") == record_id
                        && call.get("limit").and_then(Value::as_u64) == limit
                        && call.get("cursor") == next_cursor
                })
        }
        Some(false) => {
            next_cursor.is_some_and(Value::is_null) && next_call.is_some_and(Value::is_null)
        }
        None => false,
    };
    let valid = value.get("format").and_then(Value::as_str) == Some("native.manage-links-list.v1")
        && record_id.is_some_and(link_nonblank)
        && value.get("viewer_relative").and_then(Value::as_bool) == Some(true)
        && value.get("query_basis").and_then(Value::as_str) == Some("live_at_each_page_read")
        && value.get("scope").and_then(Value::as_str)
            == Some("opposite_endpoint_viewable_at_read_time")
        && limit.is_some_and(|limit| (1..=200).contains(&limit))
        && cursor_valid
        && outgoing.is_some()
        && incoming.is_some()
        && outgoing
            .zip(incoming)
            .is_some_and(|(out, incoming)| out.len() + incoming.len() <= MANAGE_LINKS_ROW_LIMIT)
        && outgoing.zip(incoming).is_some_and(|(out, incoming)| {
            out.iter()
                .all(|link| link_row_valid(link, "out", record_id.unwrap()))
                && incoming
                    .iter()
                    .all(|link| link_row_valid(link, "in", record_id.unwrap()))
        })
        && returned
            == outgoing
                .zip(incoming)
                .map(|(out, incoming)| (out.len() + incoming.len()) as u64)
        && returned
            .zip(limit)
            .is_some_and(|(returned, limit)| returned <= limit)
        && continuation_valid;
    if !valid {
        return format!(
            "Link list response is malformed and no page claim was inferred; {READ_JSON_RECOVERY}\n"
        );
    }

    let outgoing = outgoing.unwrap();
    let incoming = incoming.unwrap();
    let mut out = format!(
        "Link list returned {} caller-visible row(s) for {} in this live page.\n",
        returned.unwrap(),
        inline_json(record_id.unwrap())
    );
    let mut remaining = MANAGE_LINKS_TEXT_BUDGET.saturating_sub(out.chars().count());
    render_bounded_context_component(
        &mut out,
        "Live page controls: ",
        &json!({
            "limit":limit,
            "cursor":value["cursor"],
            "returned":returned,
            "has_more":has_more,
        }),
        &mut remaining,
        2_000,
    );
    out.push_str("Rows are authorization-filtered by opposite-endpoint visibility at this read; this is not a claim about inaccessible links or a frozen cross-page snapshot.\n");
    if has_more == Some(true) {
        render_bounded_context_component(
            &mut out,
            "Next manage_links request: ",
            &json!({
                "action":next_call.unwrap()["action"],
                "record_id":next_call.unwrap()["record_id"],
                "limit":next_call.unwrap()["limit"],
                "cursor":next_call.unwrap()["cursor"],
            }),
            &mut remaining,
            2_000,
        );
        link_render_unknowns(
            &mut out,
            "next-call",
            next_call.unwrap(),
            |key| matches!(key, "action" | "record_id" | "limit" | "cursor"),
            &mut remaining,
        );
    } else {
        out.push_str("No continuation cursor was issued; this live candidate scan is exhausted.\n");
    }

    let mut rendered = 0usize;
    let mut omitted = 0usize;
    for (direction, rows) in [("out", outgoing), ("in", incoming)] {
        for link in rows {
            let row = json!({
                "direction":direction,
                "id":link["id"],
                "source_id":link["source_id"],
                "relationship":link["relationship"],
                "target_id":link["target_id"],
                "note":link["note"],
                "created_at":link["created_at"],
            });
            if !render_bounded_context_component(
                &mut out,
                "- Link row: ",
                &row,
                &mut remaining,
                1_500,
            ) {
                omitted += 1;
                continue;
            }
            rendered += 1;
            link_render_unknowns(
                &mut out,
                "link row",
                link,
                |key| {
                    matches!(
                        key,
                        "id" | "source_id" | "target_id" | "relationship" | "note" | "created_at"
                    )
                },
                &mut remaining,
            );
        }
    }
    if omitted > 0 {
        let _ = writeln!(
            out,
            "Link row detail: {rendered} rendered, {omitted} omitted by the shared text budget; {READ_JSON_RECOVERY}"
        );
    }
    link_render_unknowns(
        &mut out,
        "manage-links list",
        value,
        |key| {
            matches!(
                key,
                "action"
                    | "format"
                    | "record_id"
                    | "viewer_relative"
                    | "query_basis"
                    | "scope"
                    | "limit"
                    | "cursor"
                    | "links_out"
                    | "links_in"
                    | "returned"
                    | "has_more"
                    | "next_cursor"
                    | "next_call"
                    | "run_context"
            )
        },
        &mut remaining,
    );
    out
}

fn render_manage_facet_observations(value: &Value) -> String {
    if let Some(status) = string(value, "status") {
        let mut out = format!(
            "Facet observation {status}: {} · {} @ {} (event {})\n",
            string(value, "record_id").unwrap_or_default(),
            string(value, "key").unwrap_or_default(),
            string(value, "as_of").unwrap_or_default(),
            value
                .get("event_seq")
                .and_then(Value::as_i64)
                .unwrap_or_default(),
        );
        if value
            .get("current_value_unchanged")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            let _ = writeln!(
                out,
                "Current facet value unchanged — set it via {}",
                string(value, "current_value_written_by")
                    .unwrap_or_else(|| "update_record.facets".to_string()),
            );
        }
        render_previous_seq(&mut out, value);
        return out;
    }

    let observations = array(value, "observations");
    let mut out = format!(
        "Facet observations for {} · {} — {} returned, oldest first\n",
        string(value, "record_id").unwrap_or_default(),
        string(value, "key").unwrap_or_default(),
        observations.len(),
    );
    for observation in observations {
        let _ = write!(
            out,
            "  {}  {}",
            string(observation, "as_of").unwrap_or_default(),
            string(observation, "op").unwrap_or_default(),
        );
        if let Some(found) = observation.get("value") {
            let _ = write!(out, " {}", display_value(found));
        }
        if let Some(vocab_ref) = string(observation, "vocab_ref") {
            let _ = write!(out, " · {vocab_ref}");
        }
        if let Some(observed_at) = string(observation, "observed_at") {
            let _ = write!(out, " · observed {observed_at}");
        }
        if let Some(event_seq) = observation.get("event_seq").and_then(Value::as_i64) {
            let _ = write!(out, " · event {event_seq}");
        }
        out.push('\n');
    }
    if let Some(cursor) = string(value, "next_after_as_of") {
        let _ = writeln!(out, "Next page: after_as_of={cursor}");
    } else {
        out.push_str("No next page.\n");
    }
    out
}

fn render_facet_values(out: &mut String, heading: &str, values: &[Value]) {
    let _ = writeln!(out, "{heading} ({})", values.len());
    for value in values {
        let key = string(value, "key")
            .or_else(|| string(value, "value"))
            .or_else(|| string(value, "id"))
            .unwrap_or_default();
        let _ = write!(out, "  {key}");
        if let Some(object) = value.as_object() {
            for (field, found) in object {
                if ["key", "value", "id"].contains(&field.as_str()) {
                    continue;
                }
                let _ = write!(out, " · {field} {}", display_value(found));
            }
            if let Some(found) = object.get("value") {
                let _ = write!(out, " · value {}", display_value(found));
            }
            if let Some(id) = object.get("id") {
                let _ = write!(out, " · id {}", display_value(id));
            }
        }
        out.push('\n');
    }
}

fn render_resolve_facets(value: &Value) -> String {
    let mut out = String::new();
    if let Some(id) = string(value, "record_id") {
        let _ = write!(out, "Facets for record {id}");
    } else {
        out.push_str("Facet shape");
    }
    if let Some(record_type) = string(value, "type") {
        let _ = write!(out, " ({record_type})");
    }
    if let Some(kind) = string(value, "kind") {
        let _ = write!(out, " kind:{kind}");
    }
    if boolean(value, "archived") == Some(true) {
        out.push_str(" [archived]");
    }
    if boolean(value, "bears_shape") == Some(true) {
        out.push_str(" [bears-shape]");
    }
    out.push('\n');
    if let Some(spine) = value.get("spine") {
        let _ = writeln!(out, "Spine: {}", inline_json(spine));
    }
    if let Some(shape) = value.get("shape") {
        let _ = writeln!(out, "Resolved shape: {}", inline_json(shape));
    }
    if let Some(pack) = value.get("pack_shape") {
        let _ = writeln!(out, "Pack shape: {}", inline_json(pack));
    }
    if let Some(provenance) = value.get("provenance") {
        let _ = writeln!(out, "Provenance: {}", inline_json(provenance));
    }
    if let Some(bearer_id) = string(value, "shape_bearer_id") {
        let _ = writeln!(out, "Shape bearer: {bearer_id}");
    }
    if let Some(kind_shapes) = value.get("kind_shapes") {
        let _ = writeln!(out, "Kind shapes: {}", inline_json(kind_shapes));
    }
    if let Some(guarantee) = value.get("shape_guarantee") {
        let _ = writeln!(out, "Shape guarantee: {}", inline_json(guarantee));
    }
    if value.get("values").is_some() {
        render_facet_values(&mut out, "Current values", array(value, "values"));
    }
    render_fields(
        &mut out,
        value,
        &[
            "record_id",
            "type",
            "kind",
            "bears_shape",
            "spine",
            "archived",
            "shape",
            "pack_shape",
            "provenance",
            "values",
            "shape_guarantee",
            "shape_bearer_id",
            "kind_shapes",
            "run_context",
        ],
    );
    out
}

fn render_suggest_facet_values(value: &Value) -> String {
    let suggestions = array(value, "suggestions");
    let mut out = format!(
        "{} suggestion(s) for {} on {}\n",
        suggestions.len(),
        string(value, "facet_key").unwrap_or_default(),
        string(value, "type").unwrap_or_default(),
    );
    match value.get("vocabulary") {
        Some(Value::Null) | None => out.push_str("No governing vocabulary.\n"),
        Some(vocabulary) => {
            let _ = writeln!(out, "Vocabulary: {}", inline_json(vocabulary));
        }
    }
    if let Some(kind) = value.get("kind") {
        let _ = writeln!(out, "Kind: {}", inline_json(kind));
    }
    if let Some(declared) = value.get("declared_type") {
        let _ = writeln!(out, "Declared facet type: {}", inline_json(declared));
    }
    if let Some(guarantee) = value.get("shape_guarantee") {
        let _ = writeln!(out, "Shape guarantee: {}", inline_json(guarantee));
    }
    render_facet_values(&mut out, "Suggestions", suggestions);
    render_fields(
        &mut out,
        value,
        &[
            "facet_key",
            "type",
            "kind",
            "declared_type",
            "vocabulary",
            "suggestions",
            "shape_guarantee",
            "run_context",
        ],
    );
    out
}

// ---------------------------------------------------------------------------
// SQL and cross-axis scan
// ---------------------------------------------------------------------------

fn render_query_sql(value: &Value) -> String {
    let columns = array(value, "columns");
    let rows = array(value, "rows");
    let reported = integer(value, "row_count").unwrap_or(rows.len() as i64);
    let truncated = boolean(value, "truncated").unwrap_or(false);
    let mut out = format!("{reported} row(s) returned");
    if truncated {
        out.push_str(" — TRUNCATED at the tool ceiling; more rows may exist. Page the SQL with LIMIT/OFFSET.");
    }
    out.push('\n');
    if columns.is_empty() {
        out.push_str("Columns: none\n");
        return out;
    }
    let labels = columns
        .iter()
        .map(display_value)
        .collect::<Vec<_>>()
        .join("\t");
    let _ = writeln!(out, "{labels}");
    for row in rows {
        let cells = columns
            .iter()
            .map(|column| {
                column
                    .as_str()
                    .and_then(|name| row.get(name))
                    .map(inline_json)
                    .unwrap_or_else(|| "null".into())
            })
            .collect::<Vec<_>>()
            .join("\t");
        let _ = writeln!(out, "{cells}");
    }
    out
}

fn render_count_shape(out: &mut String, label: &str, value: &Value) {
    let buckets = array(value, "buckets");
    let _ = writeln!(
        out,
        "{label}: {} total across {} bucket(s)",
        integer(value, "total").unwrap_or_default(),
        buckets.len(),
    );
    for bucket in buckets {
        let key = bucket
            .get("key")
            .map(display_value)
            .unwrap_or_else(|| "(none)".into());
        let _ = writeln!(
            out,
            "  {key}: {}",
            integer(bucket, "count").unwrap_or_default()
        );
    }
}

fn render_scan(value: &Value) -> String {
    let corpus = integer(value, "corpus_size").unwrap_or_default();
    let mut out = format!("{corpus} record(s) in scan corpus");
    if let Some(scope) = string(value, "scope") {
        let _ = write!(out, " · scope {scope}");
    }
    out.push('\n');

    if let Some(census) = value.get("census").and_then(Value::as_object) {
        out.push_str("\nCensus\n");
        for (name, counts) in census {
            render_count_shape(&mut out, name, counts);
        }
    }

    if let Some(axes) = value.get("axes").and_then(Value::as_object) {
        out.push_str("\nAxes\n");
        for (name, axis) in axes {
            let samples = array(axis, "samples");
            let count = integer(axis, "count").unwrap_or_default();
            let quality = string(axis, "quality").unwrap_or_default();
            let _ = write!(
                out,
                "{name}: {count} in full pool · {} sample(s) shown",
                samples.len()
            );
            if !quality.is_empty() {
                let _ = write!(out, " · {quality}");
            }
            if (samples.len() as i64) < count {
                out.push_str(" (sample is a window, not the pool)");
            }
            out.push('\n');
            for sample in samples {
                let id = string(sample, "id").unwrap_or_default();
                let record_type = string(sample, "type").unwrap_or_default();
                let name = linked_record_name(sample);
                let _ = write!(out, "  {id}  {record_type}  {name}");
                if let Some(object) = sample.as_object() {
                    for (key, evidence) in object {
                        if ["id", "type", "name", "record_url", "share_url"].contains(&key.as_str())
                        {
                            continue;
                        }
                        let _ = write!(out, " · {key} {}", display_value(evidence));
                    }
                }
                out.push('\n');
            }
        }
    }

    let convergence = array(value, "convergence");
    let _ = writeln!(
        out,
        "\nConvergence ({} record(s) appearing in at least two shown sample heads)",
        convergence.len()
    );
    for record in convergence {
        let _ = writeln!(
            out,
            "  {}  {}  {} · axis_count {} · axes {}",
            string(record, "id").unwrap_or_default(),
            string(record, "type").unwrap_or_default(),
            linked_record_name(record),
            integer(record, "axis_count").unwrap_or_default(),
            record
                .get("axes")
                .map(inline_json)
                .unwrap_or_else(|| "[]".into()),
        );
        if let Some(object) = record.as_object() {
            for (key, evidence) in object {
                if [
                    "id",
                    "type",
                    "name",
                    "axis_count",
                    "axes",
                    "record_url",
                    "share_url",
                ]
                .contains(&key.as_str())
                {
                    continue;
                }
                let _ = writeln!(out, "    {key}: {}", display_value(evidence));
            }
        }
    }
    if let Some(thresholds) = value.get("thresholds") {
        let _ = writeln!(out, "Thresholds: {}", inline_json(thresholds));
    }
    render_fields(
        &mut out,
        value,
        &[
            "corpus_size",
            "scope",
            "census",
            "axes",
            "convergence",
            "thresholds",
            "run_context",
        ],
    );
    out
}

// ---------------------------------------------------------------------------
// Meta tier
// ---------------------------------------------------------------------------

fn render_manage_vocabularies(value: &Value) -> String {
    if value.get("values").is_some() {
        let values = array(value, "values");
        let mut out = format!("Vocabulary values ({})\n", values.len());
        if let Some(vocabulary) = value.get("vocabulary") {
            let _ = writeln!(out, "Vocabulary: {}", inline_json(vocabulary));
        }
        if let Some(reference) = string(value, "vocab_ref") {
            let _ = writeln!(out, "vocab_ref: {reference}");
        }
        if let Some(status) = string(value, "status") {
            let _ = writeln!(out, "status filter: {status}");
        }
        render_facet_values(&mut out, "Values", values);
        return out;
    }

    let mut out = String::from("Vocabulary mutation\n");
    render_fields(&mut out, value, &["run_context"]);
    out
}

fn render_manage_schema_config(value: &Value) -> String {
    if value.get("rows").is_none() {
        let mut out = String::from("Schema config mutation\n");
        render_fields(&mut out, value, &["run_context"]);
        return out;
    }

    let rows = array(value, "rows");
    let mut out = format!("Schema config — {} row(s)\n", rows.len());
    for row in rows {
        let _ = writeln!(out, "  {}", inline_json(row));
    }
    if let Some(pack) = value.get("pack") {
        let _ = writeln!(out, "Pack view: {}", inline_json(pack));
    }
    if let Some(resolved) = value.get("resolved") {
        let _ = writeln!(out, "Resolved view: {}", inline_json(resolved));
    }
    if let Some(spine) = value.get("spine_facets") {
        let _ = writeln!(out, "Spine facets: {}", inline_json(spine));
    }
    if let Some(reserved) = value.get("reserved_facets") {
        let _ = writeln!(out, "Reserved facets: {}", inline_json(reserved));
    }
    if let Some(types) = value.get("declared_facet_types") {
        let _ = writeln!(out, "Declared facet types: {}", inline_json(types));
    }
    if let Some(scope) = value.get("declared_type_scope") {
        let _ = writeln!(out, "Declared type scope: {}", inline_json(scope));
    }
    render_fields(
        &mut out,
        value,
        &[
            "rows",
            "pack",
            "resolved",
            "spine_facets",
            "reserved_facets",
            "declared_facet_types",
            "declared_type_scope",
            "run_context",
        ],
    );
    out
}

// ---------------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------------

fn render_attachment_created(value: &Value) -> String {
    let mut out = format!(
        "Attached {} under {}",
        string(value, "attachment_id").unwrap_or_default(),
        string(value, "record_id").unwrap_or_default(),
    );
    if let Some(name) = string(value, "name") {
        let _ = write!(out, " · {name}");
    }
    out.push('\n');
    if let Some(blob) = value.get("blob") {
        let _ = writeln!(out, "Blob: {}", inline_json(blob));
    }
    render_fields(
        &mut out,
        value,
        &["attachment_id", "record_id", "name", "blob", "run_context"],
    );
    out
}

fn render_read_attachment(value: &Value) -> String {
    let offset = integer(value, "offset").unwrap_or_default();
    let length = integer(value, "length").unwrap_or_default();
    let eof = boolean(value, "eof").unwrap_or(false);
    let next = offset + length;
    let mut out = format!(
        "Attachment {} · {} · ",
        string(value, "attachment_id").unwrap_or_default(),
        string(value, "name").unwrap_or_default(),
    );
    if length == 0 {
        let _ = write!(out, "no bytes returned at offset {offset}");
    } else {
        let _ = write!(out, "bytes {offset}–{}", next - 1);
    }
    if eof {
        out.push_str(" · EOF");
    } else {
        let _ = write!(
            out,
            " · window only; more bytes available (set offset to {next})"
        );
    }
    if let Some(deleted) = string(value, "deleted_at") {
        let _ = write!(out, " · detached {deleted}");
    }
    out.push('\n');
    if let Some(blob) = value.get("blob") {
        let _ = writeln!(out, "Blob: {}", inline_json(blob));
    }
    let encoding = string(value, "content_encoding").unwrap_or_default();
    let _ = writeln!(out, "Content ({encoding}, {length} byte(s)):");
    if let Some(content) = string(value, "content") {
        out.push_str(&content);
        if !content.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

fn render_manage_attachments(value: &Value) -> String {
    if value.get("attachments").is_some() {
        let attachments = array(value, "attachments");
        let mut out = format!(
            "{} attachment(s) under {} (complete unwindowed list)\n",
            attachments.len(),
            string(value, "record_id").unwrap_or_default(),
        );
        for attachment in attachments {
            let _ = writeln!(out, "  {}", inline_json(attachment));
        }
        return out;
    }
    if boolean(value, "detached") == Some(true) && value.get("blob_retained").is_some() {
        return format!(
            "Detached {} · blob {} retained: {}\n",
            string(value, "attachment_id").unwrap_or_default(),
            string(value, "blob_id").unwrap_or_default(),
            boolean(value, "blob_retained").unwrap_or(false),
        );
    }

    let mut out = format!(
        "Attachment {}",
        string(value, "attachment_id").unwrap_or_default()
    );
    if let Some(name) = string(value, "name") {
        let _ = write!(out, " · {name}");
    }
    if boolean(value, "detached") == Some(true) {
        out.push_str(" · detached");
    }
    out.push('\n');
    render_fields(
        &mut out,
        value,
        &["attachment_id", "name", "detached", "run_context"],
    );
    out
}

// ---------------------------------------------------------------------------
// Work
// ---------------------------------------------------------------------------

fn render_context_entries(out: &mut String, heading: &str, entries: &[Value]) {
    let _ = writeln!(out, "{heading} ({})", entries.len());
    for entry in entries {
        // Full JSON here is deliberate: governance/dependency entries carry
        // relationship direction, lifecycle, note and summary, all of which
        // may change the action a claimant takes.
        let _ = writeln!(out, "  {}", inline_json(entry));
    }
}

fn render_resolve_suggestions(value: &Value) -> String {
    let status = string(value, "status").unwrap_or_else(|| "unknown".into());
    let target = string(value, "target_id").unwrap_or_default();
    let ids = join_strings(array(value, "suggestion_ids"));
    let mut out = format!("Suggestion resolution: {status} · target {target}");
    if !ids.is_empty() {
        let _ = write!(out, " · suggestions {ids}");
    }
    out.push('\n');
    for cause in array(value, "causes") {
        let id = string(cause, "suggestion_id").unwrap_or_default();
        let code = string(cause, "code").unwrap_or_else(|| "unknown".into());
        let _ = writeln!(out, "  {id}: {code} ({})", inline_json(cause));
    }
    out
}

fn render_start_work(value: &Value) -> String {
    let mut out = format!(
        "Work {} on {} · {}",
        string(value, "action").unwrap_or_default(),
        string(value, "record_id").unwrap_or_default(),
        if boolean(value, "changed").unwrap_or(false) {
            "state changed"
        } else {
            "no state change"
        },
    );
    if let Some(lifecycle) = string(value, "lifecycle") {
        let _ = write!(out, " · lifecycle {lifecycle}");
    }
    let _ = write!(
        out,
        " · {}",
        if boolean(value, "claimed").unwrap_or(false) {
            "claimed"
        } else {
            "unclaimed"
        }
    );
    if let Some(account) = string(value, "held_by_account") {
        let _ = write!(out, " · held by account {account}");
        if let Some(run_key) = string(value, "held_by_run_key") {
            let _ = write!(out, " · run {run_key}");
        }
    } else if let Some(holder) = string(value, "held_by") {
        let _ = write!(out, " · held by {holder}");
    }
    if let Some(claimed_at) = string(value, "claimed_at") {
        let _ = write!(out, " · claimed at {claimed_at}");
    }
    out.push('\n');

    let context = value.get("context").cloned().unwrap_or(Value::Null);
    if let Some(record) = context.get("record") {
        out.push('\n');
        out.push_str(&render_get_record(
            &json!({
                "records": [record],
                "children_limit": 200,
                "children_offset": 0,
                "links_limit": 200,
                "links_offset": 0,
            }),
            false,
        ));
    }
    out.push('\n');
    render_context_entries(&mut out, "Governance", array(&context, "governance"));
    let dependencies = context.get("dependencies").cloned().unwrap_or(Value::Null);
    let ready = boolean(&dependencies, "ready").unwrap_or(false);
    let _ = writeln!(out, "Dependencies — ready: {ready}");
    render_context_entries(&mut out, "Waiting on", array(&dependencies, "waiting_on"));
    render_context_entries(&mut out, "Satisfied", array(&dependencies, "satisfied"));
    render_context_entries(&mut out, "Blocked by", array(&dependencies, "blocked_by"));
    let comments = context.get("comments").cloned().unwrap_or(Value::Null);
    let open_count = integer(&comments, "open_thread_count").unwrap_or(0);
    let threads = array(&comments, "open_threads");
    let _ = writeln!(out, "Open comment threads ({open_count})");
    for thread in threads {
        let root = thread.get("root").unwrap_or(&Value::Null);
        let body = string(root, "body").unwrap_or_default();
        let (preview, shortened) = one_line_preview(&body, 240);
        let _ = writeln!(
            out,
            "  {}  {}{}",
            string(root, "id").unwrap_or_default(),
            preview,
            if shortened { " (body shortened)" } else { "" }
        );
        render_comment_target(&mut out, root, "    ");
        for reply in array(thread, "replies") {
            let reply_body = string(reply, "body").unwrap_or_default();
            let (reply_preview, reply_shortened) = one_line_preview(&reply_body, 240);
            let _ = writeln!(
                out,
                "    reply {}  {}{}",
                string(reply, "id").unwrap_or_default(),
                reply_preview,
                if reply_shortened {
                    " (body shortened)"
                } else {
                    ""
                }
            );
        }
        let reply_count = integer(thread, "reply_count").unwrap_or(0);
        let shown = array(thread, "replies").len() as i64;
        if reply_count > shown {
            let _ = writeln!(out, "    {shown} of {reply_count} replies shown");
        }
    }
    out
}

#[cfg(test)]
mod record_url_render_tests {
    use serde_json::json;

    use super::render;

    #[test]
    fn record_renderers_prefer_share_url_and_fall_back_to_record_url() {
        let shared = json!({
            "shape": "records",
            "records": [{
                "id": "0189d4c6-1f2a-7b3c-9d4e-5f60718293a4",
                "type": "Document",
                "name": "Roadmap [Q4]",
                "record_url": "https://app.withnative.ai/0189d4c",
                "share_url": "https://n8v.to/0189d4c"
            }],
            "total": 1,
            "returned": 1,
            "has_more": false,
            "offset": 0
        });
        let query = render("query_record", &shared).unwrap();
        assert!(
            query.contains("[Roadmap \\[Q4\\]](https://n8v.to/0189d4c)"),
            "{query}"
        );
        assert!(!query.contains("app.withnative.ai"), "{query}");

        let aggregate = render(
            "query_record",
            &json!({
                "shape": "aggregate",
                "op": "sum",
                "facet_key": "amount",
                "value": 12.5,
                "matched_records": 3,
                "contributing_values": 2,
                "missing_values": 0,
                "non_numeric_values": 1,
                "messages": ["lane miss\nAggregate operation: forged"]
            }),
        )
        .unwrap();
        assert!(aggregate.contains("\"sum\""), "{aggregate}");
        assert!(aggregate.contains("\"amount\""), "{aggregate}");
        assert!(
            aggregate.contains("lane miss\\nAggregate operation: forged"),
            "{aggregate}"
        );
        assert!(
            !aggregate
                .lines()
                .any(|line| line == "Aggregate operation: forged"),
            "{aggregate}"
        );

        let counts = render(
            "query_record",
            &json!({
                "shape": "counts",
                "total": 2,
                "buckets": [
                    {"key": null, "count": 1},
                    {"key": "(none)\nforged", "count": 1}
                ]
            }),
        )
        .unwrap();
        assert!(counts.contains("  null  1"), "{counts}");
        assert!(counts.contains("\"(none)\\nforged\""), "{counts}");
        assert!(
            !counts.lines().any(|line| line == "forged\"  1"),
            "{counts}"
        );

        let next_request = json!({
            "steps": [{"step": "filter", "ids": ["rec:visible"]}],
            "activity": {"after_local_seq": 9, "through_local_seq": 12}
        });
        let activity = render(
            "query_record",
            &json!({
                "shape": "activity",
                "activities": [{
                    "event": {
                        "local_seq": 9,
                        "id": "evt:9",
                        "record_id": "rec:visible",
                        "type": "record.updated",
                        "payload": {"summary": "safe\nAdditional query fields omitted from text: forged"},
                        "actor": null,
                        "created_at": "2026-08-28T00:00:00Z"
                    },
                    "matches": [{
                        "kind": "field_transition",
                        "clause": 0,
                        "field": "summary",
                        "before": "old",
                        "after": "new",
                        "future_secret": "not echoed evidence"
                    }]
                }],
                "matched_event_count": 1,
                "local_database_id": "db:test",
                "high_water_local_seq": 12,
                "subject_as_of_local_seq": 7,
                "has_more": true,
                "next_request": next_request
            }),
        )
        .unwrap();
        assert!(
            activity.contains("Pinned subject membership at local seq 7"),
            "{activity}"
        );
        assert!(
            activity.contains(&format!(
                "next_request: {}",
                super::inline_json(&next_request)
            )),
            "{activity}"
        );
        for sentinel in ["field_transition", "summary", "old", "new"] {
            assert!(
                activity.contains(sentinel),
                "missing {sentinel}:\n{activity}"
            );
        }
        assert!(activity.contains("future_secret"), "{activity}");
        assert!(!activity.contains("not echoed evidence"), "{activity}");
        assert!(
            !activity
                .lines()
                .any(|line| line == "Additional query fields omitted from text: forged"),
            "{activity}"
        );

        let capped = render(
            "query_record",
            &json!({
                "shape": "activity",
                "activities": [{
                    "event": {"local_seq": 1, "record_id": "rec:visible", "type": "record.updated"},
                    "matches": (0..101).map(|clause| json!({
                        "kind": "event", "clause": clause, "changed_fields": []
                    })).collect::<Vec<_>>()
                }],
                "matched_event_count": 1,
                "local_database_id": "db:test",
                "high_water_local_seq": 1,
                "subject_as_of_local_seq": 1,
                "has_more": false,
                "next_request": null
            }),
        )
        .unwrap();
        assert!(capped.contains("100 of 101 row(s) shown"), "{capped}");
        assert!(capped.contains("Activity window exhausted"), "{capped}");

        let heavy_events = (0..25)
            .map(|seq| {
                json!({
                    "event": {
                        "local_seq": seq,
                        "record_id": "rec:visible",
                        "type": "record.updated",
                        "intent": "i".repeat(2_000),
                        "payload": {"body": "b".repeat(2_000)}
                    },
                    "matches": []
                })
            })
            .collect::<Vec<_>>();
        let bounded = render(
            "query_record",
            &json!({
                "shape": "activity",
                "activities": heavy_events,
                "matched_event_count": 25,
                "local_database_id": "db:test",
                "high_water_local_seq": 25,
                "subject_as_of_local_seq": 25,
                "has_more": false,
                "next_request": null
            }),
        )
        .unwrap();
        assert!(
            bounded.contains("Event detail budget exhausted"),
            "{bounded}"
        );
        assert!(bounded.chars().count() < 30_000, "{bounded}");

        let boundary_events = (0..11)
            .map(|seq| {
                let mut event = json!({
                    "local_seq": seq,
                    "record_id": "rec:visible",
                    "type": "record.updated",
                    "intent": "i".repeat(2_000)
                });
                if seq != 9 {
                    event["payload"] = json!({
                        "body": if seq == 10 {
                            "FINAL_PAYLOAD_MUST_BE_DISCLOSED_AS_OMITTED".to_string()
                        } else {
                            "b".repeat(2_000)
                        }
                    });
                }
                json!({"event": event, "matches": []})
            })
            .collect::<Vec<_>>();
        let boundary = render(
            "query_record",
            &json!({
                "shape": "activity",
                "activities": boundary_events,
                "matched_event_count": 11,
                "local_database_id": "db:test",
                "high_water_local_seq": 11,
                "subject_as_of_local_seq": 11,
                "has_more": false,
                "next_request": null
            }),
        )
        .unwrap();
        assert!(
            boundary.contains("Event detail budget exhausted"),
            "{boundary}"
        );
        assert!(
            !boundary.contains("FINAL_PAYLOAD_MUST_BE_DISCLOSED_AS_OMITTED"),
            "{boundary}"
        );

        let federated = render(
            "query_record",
            &json!({
                "scope": {"lens_id": "lens:test"},
                "complete": false,
                "failures": [{"db_id": "db:failed", "code": "timeout"}],
                "effective_limits": {"page_size": 50},
                "supplementary": [],
                "results": [{
                    "ref": {"db_id": "db:ok", "record_id": "rec:federated"},
                    "provenance": {"source_label": "Primary"},
                    "source_rank": 1,
                    "merge_score": null,
                    "sort_tuple": [1],
                    "source_elapsed_ms": 4,
                    "source_revision": "rev:1",
                    "record": {
                        "id": "rec:federated",
                        "type": "Document",
                        "kind": "note",
                        "name": "Federated result",
                        "body": "omitted body"
                    }
                }],
                "next_cursor": "cursor:next"
            }),
        )
        .unwrap();
        assert!(federated.contains("partial source coverage"), "{federated}");
        assert!(federated.contains("db:failed"), "{federated}");
        assert!(federated.contains("cursor:next"), "{federated}");
        assert!(federated.contains("rec:federated"), "{federated}");
        assert!(
            federated.contains("\"body\":\"omitted body\""),
            "{federated}"
        );
        assert!(!federated.contains("0 match(es)"), "{federated}");

        let unknown = render(
            "query_record",
            &json!({"shape": "future_shape", "future_rows": [{"secret": "not echoed"}]}),
        )
        .unwrap();
        assert!(
            unknown.contains("Unsupported query result shape"),
            "{unknown}"
        );
        assert!(unknown.contains("future_rows"), "{unknown}");
        assert!(!unknown.contains("not echoed"), "{unknown}");
        assert!(!unknown.contains("0 match(es)"), "{unknown}");

        let canonical = json!({"records": [{
            "id": "0189d4c6-1f2a-7b3c-9d4e-5f60718293a4",
            "type": "Document",
            "name": "Roadmap",
            "record_url": "https://app.withnative.ai/0189d4c"
        }]});
        let get = render("get_record", &canonical).unwrap();
        assert!(
            get.contains("[Roadmap](https://app.withnative.ai/0189d4c)"),
            "{get}"
        );
    }

    #[test]
    fn search_text_exposes_the_preferred_resolvable_record_link() {
        let value = json!({
            "query": "roadmap",
            "total": 1,
            "hits": [{
                "id": "0189d4c6-1f2a-7b3c-9d4e-5f60718293a4",
                "type": "Document",
                "name": "Roadmap",
                "score": 1.0,
                "record_url": "https://app.withnative.ai/0189d4c",
                "share_url": "https://n8v.to/0189d4c"
            }]
        });

        let rendered = render("search", &value).unwrap();

        assert!(
            rendered.contains("[Roadmap](https://n8v.to/0189d4c)"),
            "{rendered}"
        );
    }

    #[test]
    fn semantic_bulk_renderers_keep_positional_outcomes_visible() {
        let created = render(
            "create_many",
            &json!({
                "ok":false,
                "ids":["rec:a",null,"rec:c"],
                "errors":[{"index":1,"code":"dependency_failed","message":"depends on item 0"}]
            }),
        )
        .unwrap();
        assert!(created.contains("Created 2/3"), "{created}");
        assert!(created.contains("[1] dependency_failed"), "{created}");

        let resolved = render(
            "resolve_many",
            &json!({
                "counts":{"resolved":1,"not_found":1,"ambiguous":0},
                "include_archived":false,
                "results":[
                    {"index":0,"input":"Ada","status":"resolved","match":{"id":"rec:ada","name":"Ada","type":"Entity","kind":"person"}},
                    {"index":1,"input":"Missing","status":"not_found"}
                ]
            }),
        )
        .unwrap();
        assert!(resolved.contains("1 resolved · 1 not found"), "{resolved}");
        assert!(resolved.contains("[0] \"Ada\" → rec:ada"), "{resolved}");
        assert!(
            resolved.contains("[1] \"Missing\" → not found"),
            "{resolved}"
        );

        let updated = render(
            "update_record",
            &json!({
                "requested":2,
                "changed":1,
                "unchanged":1,
                "results":[
                    {"index":0,"id":"0189d4c6-1f2a-7b3c-9d4e-5f60718293a4","status":"changed"},
                    {"index":1,"id":"0189d4c6-1f2a-7b3c-9d4e-5f60718293a5","status":"unchanged"}
                ]
            }),
        )
        .unwrap();
        assert!(
            updated.contains("2 requested · 1 changed · 1 unchanged"),
            "{updated}"
        );
        assert!(updated.contains("[0] 0189d4c6"), "{updated}");
        assert!(updated.contains("[1] 0189d4c6"), "{updated}");
    }
}
