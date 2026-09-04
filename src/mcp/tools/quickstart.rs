//! Build-owned product launcher for Native's canonical Bootstrap orientation.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::db::Db;
use crate::error::Result;

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::parse_args;

pub const CONTRACT: &str = "native.quickstart.v1";

/// Tools that QuickStart's Bootstrap handoff can present as actionable next
/// steps. This is the build-owned workflow contract: named discovery profiles
/// must keep this whole set visible whenever they advertise `quickstart`.
///
/// Keep this list explicit and adjacent to [`CONTRACT`]. The rendered guidance
/// is human-facing prose, not a dependency language and must never be parsed to
/// infer workflow closure.
pub const ACTIONABLE_DEPENDENCIES: &[&str] = &[
    "bootstrap",
    "set_intent",
    "get_record",
    "get_dashboard",
    "get_structure",
    "manage_onboarding",
    "read_guide",
    "manage_instructions",
];

pub(crate) fn validate_actionable_dependency_closure<'a>(
    surface: &str,
    profile: super::super::ExposureProfile,
    advertised_names: impl IntoIterator<Item = &'a str>,
) -> Result<()> {
    let advertised = advertised_names
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    if !advertised.contains("quickstart") {
        return Ok(());
    }
    let missing = ACTIONABLE_DEPENDENCIES
        .iter()
        .copied()
        .filter(|name| !advertised.contains(name))
        .collect::<Vec<_>>();
    if missing.is_empty() {
        return Ok(());
    }
    Err(crate::error::Error::engine(format!(
        "{surface} {} profile advertises quickstart but hides actionable dependencies: {}",
        profile.as_str(),
        missing.join(", ")
    )))
}

pub const MARKDOWN: &str = r#"# Native QuickStart

Welcome to Native!

This QuickStart is for AI agents who are helping a human principal get set up on Native.

Your job is to turn Native's internal context into a useful, accessible first experience.

The three most important ideas are:
1. Use the `bootstrap` tool to get initial context.
2. Focus on getting the user to experience value.
3. Don't bog the user down with internal machinery.

## Use the `bootstrap` tool to get initial context

To onboard the user effectively, you need to understand what Native is and the current user's existing Native context.

Call the read-only `bootstrap` tool from this MCP server before giving substantive onboarding guidance when the client permits it. If the client requires explicit permission for another tool call, request or await that permission rather than guessing what Bootstrap would return.

## Focus on getting the user to experience value

Native's value compounds as useful context and work are deliberately recorded, kept current, and reused across sessions, people, agents, and tools. Continuity and coordination improve as that shared context grows, while control and portability become increasingly important.

Onboarding should nevertheless optimise for *near-term value*. Positive early experiences help people build the understanding and habits through which that longer-term value becomes available.

## Don't bog the user down with internal machinery

Bootstrap may provide internal working context such as workspace footing, standing instructions, onboarding state, run continuity, identifiers, and actionable diagnostics. Keep healthy routine machinery as internal working context by default.

Agents should absorb routine system upkeep on the person's behalf. Narrating machinery asks the person to understand Native's implementation rather than what it can help them accomplish, and can make the product intimidating or inaccessible, especially for non-technical users.

Keeping routine mechanics internal is not a request to hide information. Native remains inspectable and under human control: explain internal details when the person asks, when they materially affect the work, or when an actionable repair requires a proportionate explanation.

Translate internal state into its human meaning. Explain outcomes, choices, and useful next steps; keep routine mechanics internal; surface mechanics when requested or materially helpful.

## Next steps

Follow the current onboarding and standing guidance returned by `bootstrap`.

If first-use onboarding is pending, give the person a seamless opening that offers the current onboarding routes, recommends a route with a user-centred reason, and follows an already-clear preference without asking them to choose again.

If no onboarding is pending, continue the person's current request without replaying onboarding.

If Bootstrap identifies an actionable repair, explain the human problem and next step plainly. Do not lead with internal classifications or identifiers.

Do not duplicate Bootstrap's orientation or standing instructions in your response. Demonstrate the relevant ideas through the work, and explain them when useful or requested.
"#;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuickstartArgs {}

async fn quickstart(_db: Db, _caller: Caller, arguments: Value) -> Result<Value> {
    let _args: QuickstartArgs = parse_args("quickstart", arguments)?;
    Ok(json!({
        "contract": {
            "id": CONTRACT,
            "version": 1,
            "read_only": true,
            "build_owned": true,
            "default_content": "markdown"
        },
        "bootstrap_handoff": {
            "tool": "bootstrap",
            "read_only": true,
            "call_before_substantive_onboarding_guidance": true,
            "permission_boundary": "If another call requires explicit permission, request or await it rather than inventing Bootstrap state."
        },
        "posture": {
            "goal": "Turn Native's internal context into a useful, accessible first experience.",
            "optimise_for": "near-term value",
            "presentation_default": "Explain outcomes, choices, and useful next steps while keeping healthy routine machinery internal.",
            "human_observability": "Explain mechanics when requested, materially helpful, or required for an actionable repair."
        }
    }))
}

pub fn register_quickstart_tool(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::Quickstart,
        "Launch Native's first-use flow. Read this build-owned guidance, then call the read-only bootstrap tool for canonical session orientation before giving substantive onboarding guidance when the client permits it. QuickStart does not inspect workspace state or issue a run key.",
        json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        quickstart,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn launcher_is_static_and_contains_no_session_projection() {
        let db = crate::create_database(":memory:").await.unwrap();
        let value = quickstart(db, Caller::authenticated("acct:test"), json!({}))
            .await
            .unwrap();
        assert_eq!(value["bootstrap_handoff"]["tool"], "bootstrap");
        assert_eq!(value["posture"]["optimise_for"], "near-term value");
        let serialized = value.to_string();
        for forbidden in [
            "run_key",
            "run_context",
            "pending_obligations",
            "workspace_root",
            "record_count",
            "schema_version",
        ] {
            assert!(!serialized.contains(forbidden), "{forbidden}: {serialized}");
        }
    }

    #[tokio::test]
    async fn launcher_does_not_advertise_or_accept_run_context_arguments() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        register_quickstart_tool(&mut registry).unwrap();
        let schema = &registry.get("quickstart").unwrap().input_schema;
        assert!(schema["properties"].get("run_key").is_none());
        assert!(schema["properties"].get("parent_key").is_none());
        for (arguments, expected) in [
            (json!({"run_key":"new"}), "run_key"),
            (json!({"parent_key":"harbor-lantern-b748b2"}), "parent_key"),
        ] {
            let error = registry
                .call(
                    db.clone(),
                    Caller::authenticated("acct:test"),
                    "quickstart",
                    arguments,
                )
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains("unknown field"), "{error}");
            assert!(error.contains(expected), "{error}");
        }
    }

    #[tokio::test]
    async fn launcher_discards_trusted_in_process_run_context_before_capture() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        register_quickstart_tool(&mut registry).unwrap();
        let caller = Caller::authenticated("acct:test")
            .with_run_context(
                Some("scout-chair-a748b2".into()),
                Some("harbor-lantern-b748b2".into()),
            )
            .with_intent(Some("must not leak into QuickStart".into()));

        registry
            .call(db.clone(), caller, "quickstart", json!({}))
            .await
            .unwrap();

        let captured: (Option<String>, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT run_key,parent_key,intent FROM read_log_calls WHERE tool='quickstart'",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(captured, (None, None, None));
    }

    #[test]
    fn launcher_copy_carries_the_handoff_value_and_non_narration_contract() {
        for required in [
            "read-only `bootstrap`",
            "near-term value",
            "absorb routine system upkeep",
            "non-technical users",
            "If no onboarding is pending",
            "actionable repair",
        ] {
            assert!(MARKDOWN.contains(required), "missing {required:?}");
        }
        for forbidden in [
            "Run key:",
            "Route:",
            "obligation ID",
            "Records visible",
            "schema version",
        ] {
            assert!(!MARKDOWN.contains(forbidden), "{forbidden}: {MARKDOWN}");
        }
    }

    #[test]
    fn actionable_dependency_contract_fails_closed_without_a_continuation() {
        let error = validate_actionable_dependency_closure(
            "test-surface",
            super::super::super::ExposureProfile::Complete,
            [
                "quickstart",
                "bootstrap",
                "set_intent",
                "get_record",
                "get_dashboard",
                "get_structure",
                "manage_onboarding",
                "read_guide",
            ],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("manage_instructions"), "{error}");
    }

    #[test]
    fn actionable_dependency_contract_covers_the_structured_bootstrap_handoff() {
        for required in std::iter::once("bootstrap")
            .chain(
                super::super::orientation::ACTIONABLE_NEXT_STEP_TOOLS
                    .iter()
                    .copied(),
            )
            .chain(["manage_onboarding", "read_guide", "manage_instructions"])
        {
            assert!(
                ACTIONABLE_DEPENDENCIES.contains(&required),
                "QuickStart dependency contract omits {required}"
            );
        }
        let unique = ACTIONABLE_DEPENDENCIES
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(unique.len(), ACTIONABLE_DEPENDENCIES.len());
    }
}
