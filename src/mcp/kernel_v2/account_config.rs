//! Private canonical account configuration, not adoption of a same-kind record.
use super::*;
use crate::authorization::Capability;
use crate::mcp::tools::account_config as v1;
use v1::{Outcome, Reason, Receipt, Status};

const KIND: &str = "focus_preferences";
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Args {
    Inspect { kind: String },
    Ensure { kind: String, reason: String },
}

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_engine_handler_for_selector_values("manage_account_config",EngineKind::KernelV2,"action",&["inspect","ensure"],|engine,caller,args| async move {
        let EngineHandle::KernelV2(db)=engine else {unreachable!()};
        if !crate::identity::account::is_account_token(caller.credential()) {
            return Err(Error::engine("manage_account_config: authenticated canonical account required"));
        }
        let actor=principal(&db,&caller).await?;
        let args: Args=parse("manage_account_config",args)?;
        let (kind,reason)=match &args { Args::Inspect {kind}=>(kind,None),Args::Ensure {kind,reason}=>(kind,Some(reason.as_str())) };
        if kind!=KIND {return Err(Error::engine("manage_account_config: unsupported kind"));}
        if reason.is_some_and(|r| r.trim().is_empty()) {return Err(Error::engine("manage_account_config: reason must be nonblank"));}
        let mut tx=if reason.is_some() {crate::db::begin_write(db.write_pool()).await?} else {db.pool().begin().await?};
        kernel::app_installs::admit_dispatched_on(&mut tx,&actor).await?;
        let account=identity_read::principal_account_on(&mut tx,&actor).await?
            .filter(|account| account==caller.credential()).ok_or_else(||Error::engine("manage_account_config: authenticated canonical account required"))?;
        // A Person is neither required nor provisioned by private-config reads.
        debug_assert_eq!(account,caller.credential());
        kernel::account_config::require_prepared_on(&mut tx).await?;
        let mapping=kernel::account_config::mapping_on(&mut tx,&actor,KIND).await?;
        kernel::account_config::verify_mapping_on(&mut tx,&actor,KIND,mapping.as_ref()).await?;
        let mut result=evaluate(&mut tx,&actor,mapping.as_ref(),true).await?;
        if let Some(reason)=reason {
            if result.status==Status::Absent {
                super::shape::stage_catalog_on(&mut tx,&actor).await?;
                let empty=json!({"version":1,"foci":[]});
                if !v1::registered(&mut tx).await? || !v1::shape(&mut tx).await?.is_some_and(|s| v1::valid_value(&s,&empty)) {
                    return Err(Error::engine("manage_account_config: kind_not_registered"));
                }
                let mut acts=crate::act::ActAllocation::new();
                use sha2::{Digest,Sha256};
                let pending=kernel::app_installs::start_app_action_in(&db,&mut tx,&actor,"manage_account_config",hex::encode(Sha256::digest(serde_json::to_vec(&json!({"action":"ensure","kind":KIND,"reason":reason}))?)),Some(reason.into()),&mut acts).await?;
                let created=super::writes::create(&db,&mut tx,&mut acts,&actor,&json!({"type":"Configuration","kind":KIND,"name":"Focus preferences","home_id":crate::schema::UNFILED_RECORD_ID,"access_policy":"account_only","persistence":"enduring","facets":{"focus.preferences":empty},"reason":reason})).await?;
                let id=created["id"].as_str().ok_or_else(||Error::engine("account config creation returned no record"))?;
                kernel::account_config::bind_in(&db,&mut tx,&mut acts,&actor,id).await?;
                let current=kernel::account_config::mapping_on(&mut tx,&actor,KIND).await?;
                result=evaluate(&mut tx,&actor,current.as_ref(),false).await?;
                if result.status!=Status::Healthy {return Err(Error::engine("account config creation failed health precondition"));}
                result.outcome=Outcome::Created; result.created=Some(true);
                let attribution=kernel::app_installs::finish_app_action_in(&db,&mut tx,&actor,pending,&mut acts).await?;
                super::shape::unstage_catalog_on(&mut tx).await?;
                db.commit_kernel_content(tx).await?;
                let mut value=receipt_value(result)?;
                if let Some(attribution)=attribution {value["app_attribution"]=attribution;}
                return Ok(value);
            }
            if result.status==Status::Healthy {result.outcome=Outcome::Existing;result.created=Some(false);} else {result=result.refused(None);}
            super::shape::unstage_catalog_on(&mut tx).await?;
            // An existing/refused ensure has no persistent effects at all.
            tx.rollback().await?;
        } else {
            tx.rollback().await?;
            if let Some(app)=caller.host_asserted_app() {kernel::app_installs::admit_account_app_as(&db,caller.credential(),app).await?;}
        }
        receipt_value(result)
    })
}

// Engine metadata is outside the eight v1 logical receipt fields. The shell
// uses it only to choose recovery guidance; no revision-string heuristics.
fn receipt_value(receipt: Receipt) -> Result<Value> {
    let mut value = serde_json::to_value(receipt)?;
    value["engine"] = json!("kernel_v2");
    Ok(value)
}

async fn evaluate(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    mapping: Option<&kernel::account_config::Mapping>,
    stage: bool,
) -> Result<Receipt> {
    let Some(mapping) = mapping else {
        return Ok(Receipt::absent());
    };
    let id = &mapping.record_id;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_records WHERE id=?)")
            .bind(id)
            .fetch_one(&mut *conn)
            .await?;
    if mapping.source_deleted
        || mapping.source_missing
        || kernel::hq::tombstoned_on(conn, id).await?
    {
        return Ok(Receipt::unusable(id, Reason::Deleted));
    }
    if !exists {
        return Ok(Receipt::unusable(
            id,
            if mapping.source_origin.is_none() {
                Reason::Deleted
            } else {
                Reason::Forbidden
            },
        ));
    }
    if !kernel::kernel_effective_capability_on(conn, actor, id)
        .await?
        .allows(Capability::Manage)
    {
        return Ok(Receipt::unusable(id, Reason::Forbidden));
    }
    let record = kernel::read_record_on(conn, actor, id)
        .await?
        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    let primary: Option<String> =
        sqlx::query_scalar("SELECT primary_type FROM main.kernel_records WHERE id=?")
            .bind(id)
            .fetch_one(&mut *conn)
            .await?;
    let (typ, kind) = v1_type_and_kind(
        record.family.as_deref(),
        record.pin.as_ref().map(|p| p.version),
        primary.as_deref(),
        record.kind.as_deref(),
        &record.fields,
    );
    if typ != Some("Configuration") || kind != Some(KIND) {
        return Ok(Receipt::unusable(id, Reason::WrongKind));
    }
    if stage {
        super::shape::stage_catalog_on(conn, actor).await?;
    }
    if !v1::registered(conn).await? {
        return Ok(Receipt::unusable(id, Reason::WrongKind));
    }
    let policy = kernel::policy_read::snapshot_on(conn, actor, id, false).await?;
    let owner: Option<String> =
        sqlx::query_scalar("SELECT owner_id FROM main.kernel_records WHERE id=?")
            .bind(id)
            .fetch_one(&mut *conn)
            .await?;
    if owner.as_deref() != Some(actor)
        || policy.target != *id
        || policy.mode != "explicit"
        || policy.anchor != *id
        || policy.entries.len() != 1
        || policy.entries[0].kind != "account"
        || policy.entries[0].subject != actor
        || policy.entries[0].capability != "manage"
    {
        return Ok(Receipt::unusable(id, Reason::PolicyNotAccountOnly));
    }
    if record.archived {
        return Ok(Receipt::unusable(id, Reason::Archived));
    }
    let facet: Option<String> = sqlx::query_scalar(
        "SELECT value FROM main.kernel_facets WHERE record_id=? AND key='focus.preferences'",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?
    .flatten();
    let valid = if let (Some(shape), Some(raw)) = (v1::shape(conn).await?, facet) {
        serde_json::from_str::<Value>(&raw).is_ok_and(|v| v1::valid_value(&shape, &v))
    } else {
        false
    };
    if !valid {
        return Ok(Receipt::unusable(id, Reason::InvalidContent));
    }
    let revision = kernel::record_metadata::updated_at_on(conn, id).await?;
    Ok(Receipt {
        status: Status::Healthy,
        record_id: Some(id.clone()),
        content_revision: Some(revision),
        policy_revision: Some(policy.revision),
        ..Receipt::absent()
    })
}
