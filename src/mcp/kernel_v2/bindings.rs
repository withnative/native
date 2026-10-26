//! v1 public binding list/add semantics; kernel identities are separate facts.
use super::*;
use kernel::identity_bindings::{self, Addition};

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_engine_handler_for_selector_values(
        "manage_bindings",
        EngineKind::KernelV2,
        "action",
        &["list", "add"],
        |engine, caller, args| async move {
            let EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            let actor = principal(&db, &caller).await?;
            let read = args["action"] == "list";
            let response = manage(&db, &actor, args).await?;
            if read {
                if let Some(app) = caller.host_asserted_app() {
                    kernel::app_installs::admit_account_app_as(&db, caller.credential(), app)
                        .await?;
                }
            }
            Ok(response)
        },
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum Args {
    List {
        record_id: String,
    },
    Add {
        record_id: String,
        binding: crate::identity::BindingClaim,
        #[serde(default)]
        canonical: bool,
        reason: String,
        if_binding_state_revision: Option<String>,
    },
}

pub(super) async fn manage(db: &Db, actor: &str, args: Value) -> Result<Value> {
    use sha2::{Digest, Sha256};
    let request_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&args)?));
    match parse("manage_bindings", args)? {
        Args::List { record_id } => {
            let mut tx = db.pool().begin().await?;
            kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
            kernel::read_record_on(&mut tx, actor, &record_id)
                .await?
                .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
            let bindings = identity_bindings::list_on(&mut tx, &record_id).await?;
            let principal: Option<String> = sqlx::query_scalar(
                "SELECT principal_id FROM kernel_message_people WHERE person_id=?",
            )
            .bind(&record_id)
            .fetch_optional(&mut *tx)
            .await?;
            let mut response = json!({"status":"listed","record_id":record_id,"bindings":bindings});
            if let Some(principal) = principal {
                response["kernel_identity"] =
                    json!({"principal_id":principal,"person_id":record_id});
            }
            Ok(response)
        }
        Args::Add {
            record_id,
            binding,
            canonical,
            reason,
            if_binding_state_revision,
        } => {
            crate::mcp::tools::require_nonblank_reason("manage_bindings", &reason)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
            let mut addition = Addition {
                record_id: record_id.clone(),
                binding,
                canonical,
                reason,
            };
            let plan = identity_bindings::plan_on(
                &mut tx,
                actor,
                &record_id,
                &addition,
                if_binding_state_revision.as_deref(),
            )
            .await?;
            if !plan.changed {
                return Ok(json!({"status":"unchanged","record_id":record_id,"changed":false}));
            }
            addition.binding = plan.claim;
            let mut acts = crate::act::ActAllocation::new();
            let pending = kernel::app_installs::start_app_action_in(
                db,
                &mut tx,
                actor,
                "manage_bindings",
                request_digest,
                Some(addition.reason.clone()),
                &mut acts,
            )
            .await?;
            crate::store::append_in(
                db,
                &mut tx,
                crate::store::AppendSpec {
                    record_id: crate::events::KERNEL_ROOT_ID.into(),
                    event_type: identity_bindings::EVENT.into(),
                    payload: serde_json::to_value(addition)?,
                    actor: Some(actor.into()),
                },
                &mut acts,
            )
            .await?;
            let mut response =
                json!({"status":"added","record_id":record_id,"changed":true,"act":acts.get()});
            if let Some(attribution) =
                kernel::app_installs::finish_app_action_in(db, &mut tx, actor, pending, &mut acts)
                    .await?
            {
                response["app_attribution"] = attribution;
            }
            db.commit_kernel_content(tx).await?;
            Ok(response)
        }
    }
}
