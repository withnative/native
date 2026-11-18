//! Governed public external identities; kernel identities remain separate facts.
use super::*;
use kernel::identity_bindings::{self, Addition};

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    let original = registry
        .get("manage_bindings")
        .ok_or_else(|| Error::engine("missing binding descriptor"))?
        .input_schema
        .clone();
    let binding = json!({"type":"object","properties":{"system":{"enum":["native-principal","native-record"]},"identifier":{"type":"string","minLength":1}},"required":["system","identifier"],"additionalProperties":false});
    registry.extend_kernel_v2_arguments("manage_bindings", json!({
        "action":{"enum":["list","add","canonicalize","remove","reconcile"]},
        "binding":binding,
        "bindings":{"type":"array","minItems":1,"items":binding},
        "if_binding_state_revision":{"type":"string","minLength":1,"description":"Opaque binding-state revision; optional atomic compare-and-set."}
    }))?;
    registry.isolate_kernel_v2_schema("manage_bindings", original)?;
    let mut schema = registry
        .get("manage_bindings")
        .expect("registered binding descriptor")
        .input_schema_for_engine(EngineKind::KernelV2)
        .clone();
    schema["properties"]
        .as_object_mut()
        .expect("binding properties")
        .remove("limit");
    registry.set_kernel_v2_schema("manage_bindings", schema)?;
    registry.register_engine_handler_for_selector_values(
        "manage_bindings",
        EngineKind::KernelV2,
        "action",
        &["list", "add", "canonicalize", "remove", "reconcile"],
        |engine, caller, args| async move {
            let EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            let actor = principal(&db, &caller).await?;
            let read = args["action"] == "list"
                || (args["action"] == "reconcile"
                    && !args.get("apply").and_then(Value::as_bool).unwrap_or(false));
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
    Canonicalize {
        record_id: String,
        binding: crate::identity::BindingClaim,
        reason: String,
        if_binding_state_revision: Option<String>,
    },
    Remove {
        record_id: String,
        binding: crate::identity::BindingClaim,
        reason: String,
        if_binding_state_revision: Option<String>,
    },
    Reconcile {
        target_record_id: String,
        expected_source_record_id: String,
        bindings: Vec<crate::identity::BindingClaim>,
        #[serde(default)]
        apply: bool,
        reason: Option<String>,
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
        request => mutate(db, actor, request_digest, request).await,
    }
}

async fn mutate(db: &Db, actor: &str, request_digest: String, request: Args) -> Result<Value> {
    let preview = matches!(&request, Args::Reconcile { apply: false, .. });
    let mut tx = if preview {
        db.pool().begin().await?
    } else {
        crate::db::begin_write(db.write_pool()).await?
    };
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    let (event_type, payload, reason, mut response, records) = match request {
        Args::Add {
            record_id,
            binding,
            canonical,
            reason,
            if_binding_state_revision,
        } => {
            crate::mcp::tools::require_nonblank_reason("manage_bindings", &reason)?;
            let mut addition = Addition {
                record_id: record_id.clone(),
                binding,
                canonical,
                reason: reason.clone(),
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
            (
                identity_bindings::EVENT,
                serde_json::to_value(addition)?,
                reason,
                json!({"status":"added","record_id":record_id,"changed":true}),
                vec![record_id],
            )
        }
        Args::Canonicalize {
            record_id,
            binding,
            reason,
            if_binding_state_revision,
        } => {
            crate::mcp::tools::require_nonblank_reason("manage_bindings", &reason)?;
            let plan = identity_bindings::canonicalize_on(
                &mut tx,
                actor,
                &record_id,
                &binding,
                if_binding_state_revision.as_deref(),
            )
            .await?;
            if !plan.changed {
                return Ok(json!({"status":"unchanged","record_id":record_id,"changed":false}));
            }
            let addition = Addition {
                record_id: record_id.clone(),
                binding: plan.claim,
                canonical: true,
                reason: reason.clone(),
            };
            (
                identity_bindings::EVENT,
                serde_json::to_value(addition)?,
                reason,
                json!({"status":"canonicalized","record_id":record_id,"changed":true}),
                vec![record_id],
            )
        }
        Args::Remove {
            record_id,
            binding,
            reason,
            if_binding_state_revision,
        } => {
            crate::mcp::tools::require_nonblank_reason("manage_bindings", &reason)?;
            let mut removal = identity_bindings::Removal {
                record_id: record_id.clone(),
                binding,
                reason: reason.clone(),
            };
            let plan = identity_bindings::remove_on(
                &mut tx,
                Some(actor),
                &removal,
                if_binding_state_revision.as_deref(),
            )
            .await?;
            if !plan.changed {
                return Ok(json!({"status":"unchanged","record_id":record_id,"changed":false}));
            }
            removal.binding = plan.claim;
            (
                identity_bindings::REMOVED_EVENT,
                serde_json::to_value(removal)?,
                reason,
                json!({"status":"removed","record_id":record_id,"changed":true}),
                vec![record_id],
            )
        }
        Args::Reconcile {
            target_record_id,
            expected_source_record_id,
            bindings,
            apply,
            reason,
            if_binding_state_revision,
        } => {
            let reason = reason.unwrap_or_default();
            if apply {
                crate::mcp::tools::require_nonblank_reason("manage_bindings", &reason)?;
            }
            let mut reconciliation = identity_bindings::Reconciliation {
                target_record_id: target_record_id.clone(),
                expected_source_record_id: expected_source_record_id.clone(),
                bindings,
                reason: reason.clone(),
            };
            let plan = identity_bindings::reconcile_on(
                &mut tx,
                Some(actor),
                &reconciliation,
                if_binding_state_revision.as_deref(),
            )
            .await?;
            reconciliation.bindings = plan.bindings.into_iter().map(|fact| fact.claim).collect();
            let mut response = json!({"status":if apply {"reconciled"}else{"preview"},"record_id":target_record_id,"from_record_id":expected_source_record_id,"to_record_id":target_record_id,"bindings":reconciliation.bindings,"changed":apply});
            if !apply {
                response["binding_state_revision"] = json!(
                    identity_bindings::revision_for_on(
                        &mut tx,
                        &[&target_record_id, &expected_source_record_id]
                    )
                    .await?
                );
                return Ok(response);
            }
            (
                identity_bindings::RECONCILED_EVENT,
                serde_json::to_value(reconciliation)?,
                reason,
                response,
                vec![target_record_id, expected_source_record_id],
            )
        }
        Args::List { .. } => unreachable!(),
    };
    let mut acts = crate::act::ActAllocation::new();
    let pending = kernel::app_installs::start_app_action_in(
        db,
        &mut tx,
        actor,
        "manage_bindings",
        request_digest,
        Some(reason),
        &mut acts,
    )
    .await?;
    let event = crate::store::append_in(
        db,
        &mut tx,
        crate::store::AppendSpec {
            record_id: crate::events::KERNEL_ROOT_ID.into(),
            event_type: event_type.into(),
            payload,
            actor: Some(actor.into()),
        },
        &mut acts,
    )
    .await?;
    // Canonical IDs and opaque fences do not expose a workspace's global log
    // or act counters to a caller who only manages these records.
    response["event_id"] = json!(event.id);
    response["binding_state_revision"] = json!(
        identity_bindings::revision_for_on(
            &mut tx,
            &records.iter().map(String::as_str).collect::<Vec<_>>()
        )
        .await?
    );
    if let Some(attribution) =
        kernel::app_installs::finish_app_action_in(db, &mut tx, actor, pending, &mut acts).await?
    {
        response["app_attribution"] = attribution;
    }
    db.commit_kernel_content(tx).await?;
    Ok(response)
}

#[cfg(test)]
#[path = "bindings_direct_tests.rs"]
mod direct_tests;
