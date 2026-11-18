//! Proposal-only allocation refusal, before ordinary ingress error decoration.
use crate::{Error, Result};
use serde_json::Value;

pub(crate) fn is_proposal(name: &str, args: &Value) -> bool {
    if name == "manage_named_views" {
        return args["action"] == "propose_view";
    }
    let executor = if name == "call_executor" {
        args["executor"].as_str().unwrap_or("")
    } else {
        name
    };
    executor == "records_read"
        && [args.get("operation"), args["arguments"].get("operation")]
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .any(|s| matches!(s, "propose_view" | "records_read.propose_view"))
}

pub(crate) fn check(name: &str, args: &Value) -> Result<()> {
    if is_proposal(name, args)
        && [args.get("run_key"), args["arguments"].get("run_key")]
            .into_iter()
            .any(|value| {
                matches!(
                    crate::runkey::validate_run_key_value(value),
                    crate::runkey::KeyOutcome::Requested { .. }
                )
            })
    {
        return Err(Error::engine(
            "propose_view cannot allocate a run; reuse the bootstrap run_key",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Keep registry reconstruction on its own shallow synchronous test stack,
    // rather than nesting it inside the production async publication fixture.
    #[test]
    #[cfg(feature = "mcp-executor-prototype")]
    fn proposal_contract_is_withheld_on_ordinary_sqlite() {
        assert!(
            super::super::executor_prototype::ordinary_input_schema_for_tests(
                "records_read",
                "propose_view"
            )
            .is_none()
        );
    }

    #[test]
    fn proposal_allocation_refusal_precedes_even_conflicting_envelopes() {
        for run in ["new", "new:scout-chair"] {
            for (name, args) in [
                (
                    "manage_named_views",
                    json!({"action":"propose_view","run_key":run}),
                ),
                (
                    "records_read",
                    json!({"operation":"propose_view","run_key":run}),
                ),
                (
                    "records_read",
                    json!({"operation":"query","arguments":{"operation":"records_read.propose_view","run_key":run}}),
                ),
                (
                    "call_executor",
                    json!({"executor":"records_read","operation":"propose_view","arguments":{"run_key":run}}),
                ),
            ] {
                assert!(check(name, &args)
                    .unwrap_err()
                    .to_string()
                    .contains("cannot allocate"));
            }
            assert!(check("records_read", &json!({"operation":"query","run_key":run})).is_ok());
            assert!(check(
                "manage_named_views",
                &json!({"action":"list_view_revisions","run_key":run})
            )
            .is_ok());
        }
        for run in [
            Value::Null,
            json!("scout-chair-a748b2"),
            json!("bad"),
            json!("new:invalid"),
        ] {
            assert!(check(
                "records_read",
                &json!({"operation":"propose_view","run_key":run})
            )
            .is_ok());
        }
    }
}
