//! Direct user schema authoring over native catalogue events.
use super::*;
use crate::authorization::Capability;
use crate::kernel::schema_configuration::{self, Written};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum Args {
    Write {
        data: Value,
        id: Option<String>,
        version_lineage: Option<String>,
        applies_to_collection_id: Option<String>,
        if_schema_state_revision: Option<String>,
    },
}

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    let original = registry
        .get("manage_schema_config")
        .ok_or_else(|| Error::engine("missing schema config descriptor"))?
        .input_schema
        .clone();
    registry.extend_kernel_v2_arguments("manage_schema_config",json!({"if_schema_state_revision":{"type":"string","description":"Optional opaque schema revision returned by a previous schema/vocabulary mutation; a mismatch appends nothing."}}))?;
    registry.isolate_kernel_v2_schema("manage_schema_config", original)?;
    registry.register_engine_handler_for_selector_values(
        "manage_schema_config",
        EngineKind::KernelV2,
        "action",
        &["write"],
        |engine, caller, args| async move {
            let EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            let Args::Write {
                data,
                id,
                version_lineage,
                applies_to_collection_id,
                if_schema_state_revision,
            } = parse("manage_schema_config", args)?;
            schema_configuration::validate_data(&data)?;
            let applies_to_collection_id = applies_to_collection_id.map(|s| {
                if s == crate::events::KERNEL_ROOT_ID {
                    "native:root".into()
                } else {
                    s
                }
            });
            let p = Written {
                id: id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                data,
                version_lineage,
                applies_to_collection_id,
            };
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let actor = principal_on(&mut tx, &caller).await?;
            let old = schema_configuration::existing_on(&mut tx, &p.id).await?;
            let needs_owner = p.applies_to_collection_id.is_none()
                || old
                    .as_ref()
                    .is_some_and(|r| r["applies_to_collection_id"].is_null());
            if needs_owner {
                let owner = caller.counter_footing().is_owner()
                    || (caller.hosting_database().is_none()
                        && !caller.is_member_copy()
                        && kernel::kernel_effective_capability_on(
                            &mut tx,
                            &actor,
                            crate::events::KERNEL_ROOT_ID,
                        )
                        .await?
                        .allows(Capability::Manage));
                if !owner {
                    return Err(Error::auth(
                        "manage_schema_config: database owner host role required for global rows",
                    ));
                }
            }
            let mut acts = crate::act::ActAllocation::new();
            let result = schema_configuration::write_in(
                &db,
                &mut tx,
                &actor,
                p,
                if_schema_state_revision.as_deref(),
                &mut acts,
            )
            .await?;
            db.commit_kernel_content(tx).await?;
            Ok(result)
        },
    )
}
