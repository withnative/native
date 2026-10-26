//! V1 policy-list shape over the kernel's own authority and policy snapshot.
use super::*;
use crate::authorization::Capability;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    action: String,
    record_id: String,
}

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_engine_handler_for_selector_values(
        "manage_record_policy",
        EngineKind::KernelV2,
        "action",
        &["list"],
        |engine, caller, args| async move {
            let EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            let actor = principal(&db, &caller).await?;
            let value = list(&db, &actor, &caller, args).await?;
            if let Some(app) = caller.host_asserted_app() {
                kernel::app_installs::admit_account_app_as(&db, caller.credential(), app).await?;
            }
            Ok(value)
        },
    )
}
fn missing() -> Error {
    Error::engine("manage_record_policy: record does not exist")
}
async fn list(db: &Db, actor: &str, caller: &Caller, args: Value) -> Result<Value> {
    let args: Args = parse("manage_record_policy", args)?;
    if args.action != "list" {
        return Err(Error::engine("policy mutations aren't available on v2 yet"));
    }
    let root_operator = caller.counter_footing().is_owner()
        && ["native:root", crate::events::KERNEL_ROOT_ID].contains(&args.record_id.as_str());
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    // Authorize before decoding or describing a policy: malformed descriptions
    // are repair information for administrators, never a View-only oracle.
    let target = if args.record_id == "native:root" {
        crate::events::KERNEL_ROOT_ID
    } else {
        args.record_id.as_str()
    };
    let capability = kernel::kernel_effective_capability_on(&mut tx, actor, target)
        .await
        .map_err(|e| match e {
            Error::Engine(s) if s == kernel::HIDDEN_OR_MISSING => missing(),
            e => e,
        })?;
    let authorized = capability.allows(Capability::Manage) || root_operator;
    if !authorized {
        return Err(missing());
    }
    if kernel::is_message_record(&mut tx, target).await? {
        return Err(Error::engine(
            "manage_record_policy: Message access uses its sealed audience; a home policy listing does not describe Message access and isn't available on v2 yet",
        ));
    }
    let snapshot = kernel::policy_read::snapshot_on(&mut tx, actor, target, root_operator).await?;
    if kernel::is_message_record(&mut tx, &snapshot.target).await? {
        return Err(Error::engine(
            "manage_record_policy: Message access uses its sealed audience; a home policy listing does not describe Message access and isn't available on v2 yet",
        ));
    }
    let mut entries = Vec::new();
    for entry in snapshot.entries {
        let subject = if entry.kind == "members" {
            json!({"kind":"members"})
        } else {
            let identity = identity_read::principal_identity_on(&mut tx,actor,&entry.subject).await?
                .ok_or_else(|| Error::engine("policy contains a non-portable subject; its complete listing is not yet available on v2"))?;
            let person = if let Some(id) = identity.person_id {
                kernel::read_record_on(&mut tx,actor,&id).await?.map(|record| {
                    json!({"record_id":id,"name":record.fields.get("title").or_else(||record.fields.get("name"))})
                })
            } else {
                None
            };
            json!({"kind":"account","account_id":identity.account_id,"person":person})
        };
        entries.push(json!({"subject":subject,"capability":entry.capability}));
    }
    entries.sort_by_key(|e| {
        (
            e["subject"]["kind"].as_str().unwrap_or_default().to_owned(),
            e["subject"]["account_id"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        )
    });
    tx.rollback().await?;
    let target =
        if args.record_id == "native:root" && snapshot.target == crate::events::KERNEL_ROOT_ID {
            "native:root".into()
        } else {
            snapshot.target
        };
    Ok(
        json!({"record_id":args.record_id,"authorization_target_id":target,"mode":snapshot.mode,
        "anchor_id":snapshot.anchor,"caller_capability":snapshot.capability.as_policy_str().unwrap_or("none"),
        "policy_administration_authorized":authorized,"entries":entries,"policy_revision":snapshot.revision}),
    )
}
