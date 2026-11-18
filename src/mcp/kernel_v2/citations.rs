//! Direct removal of an annotation's pinned target, preserving the annotation.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum Args {
    Remove {
        citation_id: String,
        reason: String,
        if_content_seq: Option<i64>,
    },
}

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.set_kernel_v2_schema("manage_citations", json!({
        "type":"object","properties":{
            "action":{"const":"remove"},"citation_id":{"type":"string"},
            "reason":{"type":"string","minLength":1},
            "if_content_seq":{"type":"integer","description":"Optional expected record revision; a mismatch appends nothing."}
        },"required":["action","citation_id","reason"],"additionalProperties":false
    }))?;
    registry.register_engine_handler_for_selector_values(
        "manage_citations",
        EngineKind::KernelV2,
        "action",
        &["remove"],
        |engine, caller, args| async move {
            let EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            let actor = principal(&db, &caller).await?;
            remove(&db, &actor, args).await
        },
    )
}

async fn remove(db: &Db, actor: &str, args: Value) -> Result<Value> {
    use sha2::{Digest, Sha256};
    let digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&args)?));
    let Args::Remove {
        citation_id,
        reason,
        if_content_seq,
    } = parse("manage_citations", args)?;
    if reason.trim().is_empty() {
        return Err(Error::engine("manage_citations: reason must not be blank"));
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    kernel::hq::record_edit(&mut tx, actor, &citation_id, None).await?;
    let previous: i64 =
        sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events WHERE record_id=?")
            .bind(&citation_id)
            .fetch_one(&mut *tx)
            .await?;
    if if_content_seq.is_some_and(|expected| expected != previous) {
        return Err(Error::conflict(
            "manage_citations: content revision conflict; get the record and retry",
        ));
    }
    let mut acts = crate::act::ActAllocation::new();
    let pending = kernel::app_installs::start_app_action_in(
        db,
        &mut tx,
        actor,
        "manage_citations.remove",
        digest,
        Some(reason.clone()),
        &mut acts,
    )
    .await?;
    let event = crate::store::append_in(
        db,
        &mut tx,
        crate::store::AppendSpec {
            record_id: citation_id.clone(),
            event_type: kernel::comments_v2::ANCHOR_REMOVED_EVENT.into(),
            payload: serde_json::to_value(kernel::comments_v2::AnchorRemoval {
                reason: reason.clone(),
                previous_seq: previous,
            })?,
            actor: Some(actor.into()),
        },
        &mut acts,
    )
    .await?;
    let attribution =
        kernel::app_installs::finish_app_action_in(db, &mut tx, actor, pending, &mut acts).await?;
    let mut result = json!({"citation_id":citation_id,"action":"removed",
        "reason":reason,"event_id":event.id,"act":acts.get()});
    if let Some(attribution) = attribution {
        result["app_attribution"] = attribution;
    }
    db.commit_kernel_content(tx).await?;
    Ok(result)
}
