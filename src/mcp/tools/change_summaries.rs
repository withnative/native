//! Product-safe MCP commands for the first-party change-summary workflow.
//!
//! The public surface deliberately fixes actor identity, artifact role and
//! query/output contracts at the server boundary. Callers supply semantic
//! inputs and exact concurrency fences, never generic derivation internals.

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::change_summary::{
    confirm_change_summary, create_or_reuse_change_summary, inspect_change_summary,
    query_change_summaries, request_change_summary, revoke_change_summary,
    ChangeSummaryCreateRequest, ChangeSummaryCurrentBasis, ChangeSummaryRecipePin,
    ChangeSummaryRequest, CHANGE_SUMMARY_OUTPUT_CONTRACT_ID,
    CHANGE_SUMMARY_OUTPUT_CONTRACT_VERSION,
};
use crate::derivation::{
    inspect_confirmed_artifact, ConfirmedArtifactCursor, OutputContractSelector,
    RequestRevisionApplicabilityGate, SourceRunCursor, CHANGE_SUMMARY_ROLE,
};
use crate::error::{Error, Result};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{parse_args, principal, require_nonblank_reason, REASON_DESCRIPTION};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ManageChangeSummariesArgs {
    CreateOrReuse {
        workflow_key: String,
        name: String,
        recipe: ChangeSummaryRecipePin,
        reason: String,
    },
    Derive {
        workflow_key: String,
        source_event_ids: Vec<String>,
        #[serde(default)]
        context_record_ids: Vec<String>,
        structured_result: Value,
        expected_recipe_status_event_seq: i64,
        reason: String,
    },
    Inspect {
        workflow_key: String,
    },
    Confirm {
        workflow_key: String,
        expected_revision_id: String,
        reason: String,
    },
    Revoke {
        workflow_key: String,
        reason: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum QueryChangeSummariesArgs {
    List {
        #[serde(default)]
        cursor: Option<String>,
        #[serde(default)]
        limit: Option<usize>,
        #[serde(default)]
        source_limit: Option<usize>,
    },
    Get {
        assignment_id: String,
        #[serde(default)]
        source_limit: Option<usize>,
    },
    Drill {
        assignment_id: String,
        #[serde(default)]
        cursor: Option<String>,
        #[serde(default)]
        limit: Option<usize>,
    },
}

fn live_gate(
    caller: &Caller,
) -> RequestRevisionApplicabilityGate<
    impl Fn(&str) -> Option<bool> + Send + Sync,
    ChangeSummaryCurrentBasis,
> {
    // Hosted ingress only constructs Caller after a live catalog membership
    // check. Stdio selects one in-file account. Change-summary workflows have
    // an exact single-account audience, so every other account fails closed.
    let account = caller.credential().to_owned();
    RequestRevisionApplicabilityGate::new(
        move |candidate: &str| (candidate == account).then_some(true),
        ChangeSummaryCurrentBasis,
    )
}

fn contract() -> OutputContractSelector {
    OutputContractSelector {
        id: CHANGE_SUMMARY_OUTPUT_CONTRACT_ID.into(),
        version: CHANGE_SUMMARY_OUTPUT_CONTRACT_VERSION,
    }
}

/// Inline the checked-in result schema for embedding inside a larger tool
/// descriptor. Its local `#/$defs/...` references would otherwise resolve
/// against the tool schema's root rather than the nested result schema, and
/// the TypeScript descriptor generator deliberately rejects `$ref`.
fn tool_change_summary_result_schema() -> Value {
    fn inline(root: &Value, value: &Value, depth: usize) -> Value {
        assert!(depth <= 32, "change-summary schema references are acyclic");
        match value {
            Value::Object(object) => {
                if object.len() == 1 {
                    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                        let pointer = reference
                            .strip_prefix('#')
                            .expect("change-summary schema references are document-local");
                        return inline(
                            root,
                            root.pointer(pointer)
                                .expect("change-summary schema reference resolves"),
                            depth + 1,
                        );
                    }
                }
                Value::Object(
                    object
                        .iter()
                        .filter(|(key, _)| key.as_str() != "$defs")
                        .map(|(key, nested)| (key.clone(), inline(root, nested, depth + 1)))
                        .collect(),
                )
            }
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .map(|nested| inline(root, nested, depth + 1))
                    .collect(),
            ),
            scalar => scalar.clone(),
        }
    }

    let schema = crate::change_summary::change_summary_result_schema();
    inline(&schema, &schema, 0)
}

fn opaque_cursor(kind: &str, value: &impl serde::Serialize) -> Result<String> {
    let canonical = serde_jcs::to_vec(&json!({"kind":kind,"value":value}))?;
    Ok(format!("{:x}", Sha256::digest(canonical)))
}

fn valid_opaque_cursor(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

async fn resolve_source_cursor(
    db: &crate::db::Db,
    caller: &Caller,
    assignment_id: &str,
    token: &str,
) -> Result<SourceRunCursor> {
    if !valid_opaque_cursor(token) {
        return Err(Error::engine("query_change_summaries: invalid cursor"));
    }
    let principal = principal(caller);
    let gate = live_gate(caller);
    let mut after = None;
    for _ in 0..100 {
        let item = inspect_confirmed_artifact(
            db,
            principal,
            assignment_id,
            CHANGE_SUMMARY_ROLE,
            &contract(),
            after.as_ref(),
            1,
            &gate,
        )
        .await?
        .ok_or_else(|| Error::engine("query_change_summaries: change summary unavailable"))?;
        let Some(next) = item.next_source_cursor else {
            break;
        };
        if opaque_cursor(&format!("source:{assignment_id}"), &next)? == token {
            return Ok(next);
        }
        after = Some(next);
    }
    Err(Error::engine("query_change_summaries: invalid cursor"))
}

fn public_item(mut value: Value, assignment_id: &str) -> Result<Value> {
    if let Some(cursor) = value
        .get("next_source_cursor")
        .filter(|value| !value.is_null())
    {
        value["next_source_cursor"] =
            Value::String(opaque_cursor(&format!("source:{assignment_id}"), cursor)?);
    }
    Ok(value)
}

fn tagged_result(action: &str, value: impl serde::Serialize) -> Result<Value> {
    let mut value = serde_json::to_value(value)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| Error::engine("change-summary result must be an object"))?;
    object.insert("action".into(), Value::String(action.into()));
    Ok(value)
}

async fn manage_change_summaries(
    db: crate::db::Db,
    caller: Caller,
    arguments: Value,
) -> Result<Value> {
    let args: ManageChangeSummariesArgs = parse_args("manage_change_summaries", arguments)?;
    let actor = caller.credential().to_owned();
    let run_key = caller.run_key().map(str::to_owned);
    let principal = principal(&caller);
    match args {
        ManageChangeSummariesArgs::CreateOrReuse {
            workflow_key,
            name,
            recipe,
            reason,
        } => {
            require_nonblank_reason("manage_change_summaries.create_or_reuse", &reason)?;
            tagged_result(
                "create_or_reuse",
                create_or_reuse_change_summary(
                    &db,
                    principal,
                    ChangeSummaryCreateRequest {
                        workflow_key,
                        name,
                        recipe,
                        actor,
                        run_key,
                        reason,
                    },
                )
                .await?,
            )
        }
        ManageChangeSummariesArgs::Derive {
            workflow_key,
            source_event_ids,
            context_record_ids,
            structured_result,
            expected_recipe_status_event_seq,
            reason,
        } => {
            require_nonblank_reason("manage_change_summaries.derive", &reason)?;
            if source_event_ids.len() != 3 {
                return Err(Error::engine(
                    "manage_change_summaries.derive: source_event_ids must contain exactly three authoritative runs",
                ));
            }
            let mut result = tagged_result(
                "derive",
                request_change_summary(
                    &db,
                    principal,
                    ChangeSummaryRequest {
                        workflow_key: workflow_key.clone(),
                        source_event_ids,
                        context_record_ids,
                        structured_result,
                        expected_recipe_status_event_seq,
                        actor,
                        run_key,
                        reason,
                    },
                )
                .await?,
            )?;
            result["workflow_key"] = Value::String(workflow_key);
            Ok(result)
        }
        ManageChangeSummariesArgs::Inspect { workflow_key } => tagged_result(
            "inspect",
            inspect_change_summary(&db, principal, &workflow_key).await?,
        ),
        ManageChangeSummariesArgs::Confirm {
            workflow_key,
            expected_revision_id,
            reason,
        } => {
            require_nonblank_reason("manage_change_summaries.confirm", &reason)?;
            tagged_result(
                "confirm",
                confirm_change_summary(
                    &db,
                    principal,
                    &workflow_key,
                    &expected_revision_id,
                    &actor,
                    run_key,
                    &reason,
                )
                .await?,
            )
        }
        ManageChangeSummariesArgs::Revoke {
            workflow_key,
            reason,
        } => {
            require_nonblank_reason("manage_change_summaries.revoke", &reason)?;
            tagged_result(
                "revoke",
                revoke_change_summary(&db, principal, &workflow_key, &actor, run_key, &reason)
                    .await?,
            )
        }
    }
}

async fn query_change_summaries_tool(
    db: crate::db::Db,
    caller: Caller,
    arguments: Value,
) -> Result<Value> {
    let args: QueryChangeSummariesArgs = parse_args("query_change_summaries", arguments)?;
    let principal = principal(&caller);
    match args {
        QueryChangeSummariesArgs::List {
            cursor,
            limit,
            source_limit,
        } => {
            let after = cursor.map(|token| ConfirmedArtifactCursor { token });
            let page = query_change_summaries(
                &db,
                principal,
                after.as_ref(),
                limit.unwrap_or(20),
                source_limit.unwrap_or(3),
            )
            .await?;
            let mut items = Vec::with_capacity(page.items.len());
            for item in page.items {
                let assignment = item.assignment_id.clone();
                items.push(public_item(serde_json::to_value(item)?, &assignment)?);
            }
            let next_cursor = page.next_cursor.map(|cursor| cursor.token);
            Ok(json!({"action":"list","items":items,"next_cursor":next_cursor}))
        }
        QueryChangeSummariesArgs::Get {
            assignment_id,
            source_limit,
        } => {
            let gate = live_gate(&caller);
            let item = inspect_confirmed_artifact(
                &db,
                principal,
                &assignment_id,
                CHANGE_SUMMARY_ROLE,
                &contract(),
                None,
                source_limit.unwrap_or(3),
                &gate,
            )
            .await?
            .ok_or_else(|| Error::engine("query_change_summaries: change summary unavailable"))?;
            let assignment = item.assignment_id.clone();
            let mut item = public_item(serde_json::to_value(item)?, &assignment)?;
            item["action"] = Value::String("get".into());
            Ok(item)
        }
        QueryChangeSummariesArgs::Drill {
            assignment_id,
            cursor,
            limit,
        } => {
            let after = match cursor {
                Some(token) => {
                    Some(resolve_source_cursor(&db, &caller, &assignment_id, &token).await?)
                }
                None => None,
            };
            let gate = live_gate(&caller);
            let item = inspect_confirmed_artifact(
                &db,
                principal,
                &assignment_id,
                CHANGE_SUMMARY_ROLE,
                &contract(),
                after.as_ref(),
                limit.unwrap_or(20),
                &gate,
            )
            .await?
            .ok_or_else(|| Error::engine("query_change_summaries: change summary unavailable"))?;
            Ok(json!({
                "action": "drill",
                "assignment_id": item.assignment_id,
                "target_record_id": item.target_record_id,
                "revision_id": item.revision_id,
                "source_runs": item.source_runs,
                "next_cursor": item.next_source_cursor.as_ref()
                    .map(|cursor| opaque_cursor(&format!("source:{assignment_id}"), cursor))
                    .transpose()?,
            }))
        }
    }
}

pub fn register_change_summary_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::ManageChangeSummaries,
        "Create or reuse a private Document kind:note change-summary workflow, derive one validated candidate from exact source events and context records, inspect it, explicitly confirm the selected revision for shipping, or revoke that confirmation. Actor, run provenance, artifact role and output contract are server-bound; a correction remains a draft until explicitly confirmed.",
        json!({
            "type":"object",
            "oneOf":[
                {
                    "type":"object","additionalProperties":false,
                    "properties":{
                        "action":{"const":"create_or_reuse"},"workflow_key":{"type":"string","minLength":1},
                        "name":{"type":"string","minLength":1},
                        "recipe":{
                            "type":"object","additionalProperties":false,
                            "properties":{
                                "publication_id":{"type":"string","minLength":1},
                                "descriptor_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
                                "expected_status_event_seq":{"type":"integer","minimum":1}
                            },
                            "required":["publication_id","descriptor_sha256","expected_status_event_seq"]
                        },
                        "reason":{"type":"string","minLength":1,"description":REASON_DESCRIPTION}
                    },
                    "required":["action","workflow_key","name","recipe","reason"]
                },
                {
                    "type":"object","additionalProperties":false,
                    "properties":{
                        "action":{"const":"derive"},"workflow_key":{"type":"string","minLength":1},
                        "source_event_ids":{"type":"array","minItems":3,"maxItems":3,"uniqueItems":true,"description":"Exactly three authoritative content-event ids, one for each source run.","items":{"type":"string","minLength":1}},
                        "context_record_ids":{"type":"array","maxItems":16,"uniqueItems":true,"items":{"type":"string","minLength":1}},
                        "structured_result":tool_change_summary_result_schema(),
                        "expected_recipe_status_event_seq":{"type":"integer","minimum":1},
                        "reason":{"type":"string","minLength":1,"description":REASON_DESCRIPTION}
                    },
                    "required":["action","workflow_key","source_event_ids","structured_result","expected_recipe_status_event_seq","reason"]
                },
                {
                    "type":"object","additionalProperties":false,
                    "properties":{"action":{"const":"inspect"},"workflow_key":{"type":"string","minLength":1}},
                    "required":["action","workflow_key"]
                },
                {
                    "type":"object","additionalProperties":false,
                    "properties":{
                        "action":{"const":"confirm"},"workflow_key":{"type":"string","minLength":1},
                        "expected_revision_id":{"type":"string","minLength":1},
                        "reason":{"type":"string","minLength":1,"description":REASON_DESCRIPTION}
                    },
                    "required":["action","workflow_key","expected_revision_id","reason"]
                },
                {
                    "type":"object","additionalProperties":false,
                    "properties":{
                        "action":{"const":"revoke"},"workflow_key":{"type":"string","minLength":1},
                        "reason":{"type":"string","minLength":1,"description":REASON_DESCRIPTION}
                    },
                    "required":["action","workflow_key","reason"]
                }
            ]
        }),
        manage_change_summaries,
    )?;
    registry.register(
        ToolKind::QueryChangeSummaries,
        "List only currently applicable, explicitly confirmed change-summary notes visible to the authenticated account; get one exact relationally recognized summary; or page through its authoritative evidence inputs and run provenance. Matching uses the fixed native.change-summary.markdown output contract and change_summary role, never title, kind or body heuristics. Hidden, stale and unauthorized summaries all appear unavailable.",
        json!({
            "type":"object",
            "oneOf":[
                {
                    "type":"object","additionalProperties":false,
                    "properties":{
                        "action":{"const":"list"},
                        "cursor":{"type":"string","minLength":1,"maxLength":256,"description":"Opaque continuation token returned by the preceding list page; its encoding is an engine detail."},
                        "limit":{"type":"integer","minimum":1,"maximum":100},
                        "source_limit":{"type":"integer","minimum":1,"maximum":100}
                    },
                    "required":["action"]
                },
                {
                    "type":"object","additionalProperties":false,
                    "properties":{"action":{"const":"get"},"assignment_id":{"type":"string","minLength":1},"source_limit":{"type":"integer","minimum":1,"maximum":100}},
                    "required":["action","assignment_id"]
                },
                {
                    "type":"object","additionalProperties":false,
                    "properties":{
                        "action":{"const":"drill"},"assignment_id":{"type":"string","minLength":1},
                        "cursor":{"type":"string","pattern":"^[0-9a-f]{64}$","description":"Opaque continuation returned by the preceding source page."},
                        "limit":{"type":"integer","minimum":1,"maximum":100}
                    },
                    "required":["action","assignment_id"]
                }
            ]
        }),
        query_change_summaries_tool,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};
    use crate::events::FacetSetPayload;
    use crate::recipe::{
        canonical_recipe_definition, publish_recipe_release, PublishRecipeRelease,
    };
    use uuid::Uuid;

    const ALICE: &str = "acct:change-summary-alice";
    const BOB: &str = "acct:change-summary-bob";

    async fn recipe_pin(db: &crate::Db) -> ChangeSummaryRecipePin {
        replace_explicit_policy(
            db,
            ALICE,
            crate::schema::UNFILED_RECORD_ID,
            vec![AllowEntry::account(ALICE, Capability::Manage)],
        )
        .await
        .unwrap();
        let definition = crate::change_summary::change_summary_recipe_definition().unwrap();
        let body = canonical_recipe_definition(&definition).unwrap();
        let program_id = crate::store::install_historical_record_fixture(
            db,
            crate::change_summary::CHANGE_SUMMARY_RECIPE_PROGRAM_ID,
            json!({
                "type":"Program","kind":"recipe","name":"Change summary recipe","body":body
            }),
            ALICE,
        )
        .await
        .unwrap();
        crate::store::set_facet(
            db,
            &program_id,
            FacetSetPayload {
                key: "runtime".into(),
                value: Some(crate::recipe::RECIPE_RUNTIME.into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        replace_explicit_policy(
            db,
            ALICE,
            &program_id,
            vec![AllowEntry::account(ALICE, Capability::Manage)],
        )
        .await
        .unwrap();
        let row: (String, String) = sqlx::query_as(
            "SELECT id,json_extract(payload,'$.body') FROM content_events
              WHERE record_id=? AND json_type(payload,'$.body')='text'
              ORDER BY seq DESC LIMIT 1",
        )
        .bind(&program_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        let recipe_caller = Caller::authenticated(ALICE);
        let release = publish_recipe_release(
            db,
            principal(&recipe_caller),
            PublishRecipeRelease {
                publication_event_id: Uuid::new_v4().to_string(),
                program_id,
                source_event_id: row.0,
                source_sha256: format!("{:x}", Sha256::digest(row.1.as_bytes())),
                definition,
            },
        )
        .await
        .unwrap();
        ChangeSummaryRecipePin {
            publication_id: release.descriptor.publication_event_id,
            descriptor_sha256: release.descriptor_sha256,
            expected_status_event_seq: release.status_event_seq,
        }
    }

    #[test]
    fn descriptors_expose_only_product_inputs_and_opaque_cursors() {
        let mut registry = ToolRegistry::new();
        register_change_summary_tools(&mut registry).unwrap();
        let manage = registry.get("manage_change_summaries").unwrap();
        let schema = manage.input_schema.to_string();
        assert!(!schema.contains("\"actor\""));
        assert!(!schema.contains("output_contract"));
        assert!(!schema.contains("artifact_role"));
        let derive = manage.input_schema["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|branch| {
                branch
                    .pointer("/properties/action/const")
                    .and_then(Value::as_str)
                    == Some("derive")
            })
            .unwrap();
        assert_eq!(
            derive.pointer("/properties/structured_result").unwrap(),
            &tool_change_summary_result_schema()
        );
        assert!(!derive
            .pointer("/properties/structured_result")
            .unwrap()
            .to_string()
            .contains("\"$ref\""));
        let query = registry.get("query_change_summaries").unwrap();
        let schema = query.input_schema.to_string();
        assert!(schema.contains("^[0-9a-f]{64}$"));
        assert!(!schema.contains("head_event_seq"));
        assert!(!schema.contains("confirmation_id"));
    }

    #[tokio::test]
    async fn actor_is_server_fixed_and_hidden_workflows_are_indistinguishable() {
        let db = crate::create_database(":memory:").await.unwrap();
        let pin = recipe_pin(&db).await;
        let mut registry = ToolRegistry::new();
        register_change_summary_tools(&mut registry).unwrap();
        let alice =
            Caller::authenticated(ALICE).with_run_context(Some("scout-chair-000101".into()), None);
        let created = registry
            .call(
                db.clone(),
                alice.clone(),
                "manage_change_summaries",
                json!({
                    "action":"create_or_reuse","workflow_key":"release:private",
                    "name":"Private release summary","recipe":pin,
                    "reason":"Group three authoritative runs behind an explicit shipping decision."
                }),
            )
            .await
            .unwrap();
        assert_eq!(created["workflow_key"], "release:private");
        let actor: String = sqlx::query_scalar(
            "SELECT actor FROM content_events WHERE record_id=? ORDER BY seq LIMIT 1",
        )
        .bind(created["carrier_id"].as_str().unwrap())
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(actor, ALICE);

        let spoof = registry
            .call(
                db.clone(),
                alice,
                "manage_change_summaries",
                json!({"action":"inspect","workflow_key":"release:private","actor":BOB}),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(spoof.contains("unknown field `actor`"), "{spoof}");

        let bob = Caller::authenticated(BOB);
        let hidden = registry
            .call(
                db.clone(),
                bob.clone(),
                "manage_change_summaries",
                json!({"action":"inspect","workflow_key":"release:private"}),
            )
            .await
            .unwrap_err()
            .to_string();
        let absent = registry
            .call(
                db.clone(),
                bob,
                "manage_change_summaries",
                json!({"action":"inspect","workflow_key":"release:absent"}),
            )
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(hidden, absent);
        db.close().await;
    }
}
