//! Explicit local-development transport. Expressions and admission evidence
//! come only from installed manifests, never from caller arguments.
use super::*;
use crate::mcp::{CustomInteractionPolicy, ToolExposure};

pub(crate) const TOOLS: [&str; 2] = ["describe_package_operations", "call_package_operation"];

#[derive(Deserialize)]
#[serde(untagged)]
enum Describe {
    Record(RecordDescribe),
    Exact(ExactDescribe),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordDescribe {
    record_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExactDescribe {
    scope_home: String,
    namespace: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Call {
    namespace: String,
    name: String,
    package_operation: String,
    record_id: String,
}

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    for name in TOOLS {
        let describe = name == TOOLS[0];
        let properties = if describe {
            json!({"scope_home":{"type":"string"},"namespace":{"type":"string"},"name":{"type":"string"}})
        } else {
            json!({"namespace":{"type":"string"},"name":{"type":"string"},"package_operation":{"type":"string"},"record_id":{"type":"string"}})
        };
        let required = if describe {
            json!(["scope_home", "namespace", "name"])
        } else {
            json!(["namespace", "name", "package_operation", "record_id"])
        };
        registry.register_custom(
            name, CustomInteractionPolicy::NoRecordInteractions, ToolExposure::extension(false),
            if describe {
                "LOCAL DEVELOPMENT ONLY, P1 interim. Given only record_id, discover applicable active package operations and canonical namespace/name without inferring names from record family. Or describe one exact scope_home/namespace/name selection. Discovery is bounded and complete or refuses; metadata is not authority to call. No evaluator, caller executable or validation evidence. Explicitly retry delivery drift."
            } else {
                "LOCAL DEVELOPMENT ONLY, P1 interim. Compute an installed package operation over a caller-visible record. Returns bounded provider result and server receipt only after current authority, package selection, input revision and installed-app consent/source checks. Delivery drift discards the result; explicitly retry. No automatic rerun or effects."
            },
            if describe { json!({"type":"object","oneOf":[
                {"type":"object","additionalProperties":false,"required":["record_id"],"properties":{"record_id":{"type":"string"}}},
                {"type":"object","additionalProperties":false,"required":required,"properties":properties}]})
            } else { json!({"type":"object","additionalProperties":false,"required":required,"properties":properties}) },
            |_, _, _| async { Err::<Value, _>(Error::engine("package operations require the development KernelV2 engine")) },
        )?;
        registry.declare_read_only(name)?;
        registry.mark_engine_operations_unavailable(name, EngineKind::Sqlite)?;
        registry.register_engine_handler(
            name,
            EngineKind::KernelV2,
            move |engine, caller, arguments| async move {
                let EngineHandle::KernelV2(db) = engine else {
                    unreachable!()
                };
                let actor = principal(&db, &caller).await?;
                let result = if describe {
                    let args: Describe = serde_json::from_value(arguments)?;
                    match args {
                        Describe::Record(args) => {
                            crate::package_operations::discovery::describe_record_checked(
                                &db,
                                &actor,
                                caller.credential(),
                                &args.record_id,
                                std::future::ready(()),
                            )
                            .await?
                        }
                        Describe::Exact(args) => {
                            crate::package_operations::describe_authenticated_as(
                                &db,
                                &actor,
                                caller.credential(),
                                &args.scope_home,
                                &args.namespace,
                                &args.name,
                            )
                            .await?
                        }
                    }
                } else {
                    let args: Call = serde_json::from_value(arguments)?;
                    serde_json::to_value(
                        crate::package_operations::call_authenticated_as(
                            &db,
                            &actor,
                            caller.credential(),
                            &args.namespace,
                            &args.name,
                            &args.package_operation,
                            &args.record_id,
                        )
                        .await?,
                    )?
                };
                Ok(result)
            },
        )?;
    }
    Ok(())
}
