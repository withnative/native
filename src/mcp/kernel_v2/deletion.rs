//! v1 delete_record contract over the kernel's native tombstone event.
use super::*;
use sha2::Digest;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    id: String,
    reason: String,
    #[serde(default)]
    if_content_seq: Option<i64>,
}

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_engine_handler(
        "delete_record",
        EngineKind::KernelV2,
        |engine, caller, args| async move {
            let EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            execute(db, caller, args).await
        },
    )?;
    Ok(())
}

async fn execute(db: Db, caller: Caller, args: Value) -> Result<Value> {
    let actor = principal(&db, &caller).await?;
    let args: Args = parse("delete_record", args)?;
    if args.reason.trim().is_empty() {
        return Err(Error::engine("delete_record: reason must not be blank"));
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, &actor).await?;
    let previous =
        kernel::deletion::validate_on(&mut tx, &actor, &args.id, args.if_content_seq, i64::MAX)
            .await?;
    let mut acts = crate::act::ActAllocation::new();
    let pending = kernel::app_installs::start_app_action_in(
        &db,
        &mut tx,
        &actor,
        "delete_record",
        hex::encode(sha2::Sha256::digest(serde_jcs::to_vec(
            &json!({"id":args.id,"reason":args.reason,"if_content_seq":args.if_content_seq}),
        )?)),
        Some(args.reason.clone()),
        &mut acts,
    )
    .await?;
    let event = crate::store::append_in(
        &db,
        &mut tx,
        crate::store::AppendSpec {
            record_id: args.id.clone(),
            event_type: kernel::deletion::EVENT.into(),
            payload: serde_json::to_value(kernel::deletion::Deleted {
                reason: args.reason,
                previous_seq: previous,
            })?,
            actor: Some(actor.clone()),
        },
        &mut acts,
    )
    .await?;
    let attribution =
        kernel::app_installs::finish_app_action_in(&db, &mut tx, &actor, pending, &mut acts)
            .await?;
    let mut result = json!({"id":args.id,"deleted":true,"deleted_at":event.created_at,"previous_seq":previous,"act":acts.get()});
    if let Some(attribution) = attribution {
        result["app_attribution"] = attribution;
    }
    db.commit_kernel_content(tx).await?;
    Ok(result)
}
