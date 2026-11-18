//! Ordinary probe writes. The adapter receipt and every kernel event commit
//! together; a failed field/body/facet/link operation rolls back the whole act.
use super::write_diagnostics::{phase, Stage};
use super::{parse, principal};
use crate::{
    act::ActAllocation,
    authorization::Capability,
    db::{begin_write, Db},
    kernel,
    mcp::fetch::FetchConfig,
    mcp::registry::{Caller, EngineHandle, EngineKind, ToolRegistry},
    store::AppendSpec,
    v2_standard::{relates_to as relation, v1_compat},
    Error, Result,
};
use serde_json::{json, Map, Value};
use sqlx::{Sqlite, SqliteConnection, Transaction};

#[cfg(all(feature = "v2-kernel-probe", feature = "mcp-executor-prototype"))]
use crate::kernel::original_settlement::installed::WriteAdmission;

mod batch;
mod create_many;
pub(crate) mod named_views;
pub(crate) mod publication;
pub(crate) mod replay;
pub(super) mod url_attachment;

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    register_with_fetch(registry, FetchConfig::default())
}

/// Register the v2 write handlers with an explicit fetch guard — the seam
/// the URL-attachment tests use to point `attach_from_url` at a loopback
/// server. Production callers use [`register`].
pub(super) fn register_with_fetch(
    registry: &mut ToolRegistry,
    fetch_config: FetchConfig,
) -> Result<()> {
    for tool in [
        "attach_text",
        "create_record",
        "update_record",
        "manage_links",
        "archive_record",
        "batch_write",
        "create_many",
    ] {
        registry.register_engine_handler(
            tool,
            EngineKind::KernelV2,
            move |engine, caller, args| async move {
                let EngineHandle::KernelV2(db) = engine else {
                    unreachable!()
                };
                let actor = principal(&db, &caller).await?;
                if tool == "batch_write" {
                    return batch::execute(&db, &actor, &caller, args).await;
                }
                if tool == "update_record" {
                    return execute_update_owned(
                        &db,
                        &actor,
                        &caller,
                        args,
                        #[cfg(all(
                            feature = "v2-kernel-probe",
                            feature = "mcp-executor-prototype"
                        ))]
                        None,
                    )
                    .await;
                }
                execute(&db, &actor, tool, args).await
            },
        )?;
    }
    // URL import rides its own registration (not the loop above): the fetch
    // guard is per-registry configuration, and the handler fetches with no
    // transaction open before committing, which the shared `execute` path
    // cannot express. The shared tool list above is untouched.
    let url_fetch_config = fetch_config;
    registry.register_engine_handler(
        "attach_from_url",
        EngineKind::KernelV2,
        move |engine, caller, args| {
            let url_fetch_config = url_fetch_config.clone();
            async move {
                let EngineHandle::KernelV2(db) = engine else {
                    unreachable!()
                };
                let actor = principal(&db, &caller).await?;
                url_attachment::execute(&db, &actor, args, &url_fetch_config).await
            }
        },
    )?;
    if registry.get("manage_publication").is_some() {
        registry.register_engine_handler(
            "manage_publication",
            EngineKind::KernelV2,
            |engine, caller, args| async move {
                let EngineHandle::KernelV2(db) = engine else {
                    unreachable!()
                };
                publication::execute(&db, &caller, args).await
            },
        )?;
    }
    // Pick the source route before constructing either async state. A read
    // never carries the effectful dispatcher's state (or its writer setup).
    registry.register_engine_handler(
        "manage_named_views",
        EngineKind::KernelV2,
        |engine, caller, args| -> futures::future::BoxFuture<'static, Result<Value>> {
            let EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            if args["action"] == "propose_view" {
                Box::pin(async move {
                    let actor = principal(&db, &caller).await?;
                    Box::pin(crate::named_views::proposal::execute(
                        &db, &actor, &caller, args,
                    ))
                    .await
                })
            } else {
                Box::pin(async move {
                    crate::named_views::gate::require()?;
                    if matches!(
                        args["action"].as_str(),
                        Some("activate_view" | "unpublish_view")
                    ) {
                        let action = args["action"].as_str().unwrap();
                        if !caller
                            .write_plan_execution()
                            .is_some_and(|p| p.executor == "records_write" && p.operation == action)
                        {
                            return Err(Error::engine(
                                "named view publication requires an executor write plan",
                            ));
                        }
                    }
                    let actor = principal(&db, &caller).await?;
                    named_views::execute(&db, &actor, &caller, args).await
                })
            }
        },
    )?;
    Ok(())
}

fn invalid(message: impl Into<String>) -> Error {
    Error::engine(format!("kernel-v2 write: {}", message.into()))
}
fn object(value: &Value) -> Result<&Map<String, Value>> {
    value.as_object().ok_or_else(|| invalid("expected object"))
}
fn text<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{key} must be a string")))
}
fn optional_text<'a>(args: &'a Value, key: &str) -> Result<Option<&'a str>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        _ => Err(invalid(format!("{key} must be a string or null"))),
    }
}
fn allowed(args: &Value, keys: &[&str]) -> Result<()> {
    for key in object(args)?.keys() {
        if !keys.contains(&key.as_str())
            || (!minted_ids_enabled() && matches!(key.as_str(), "id_nonce" | "attachment_id"))
        {
            return Err(invalid(format!("unsupported argument {key}")));
        }
    }
    if args.get("response_mode").is_some_and(|v| v != "full") {
        return Err(invalid("unsupported response_mode; use full"));
    }
    if let Some(reason) = args.get("reason") {
        if !reason.is_string() {
            return Err(invalid("reason must be a string"));
        }
    }
    Ok(())
}

// BEGIN IMMEDIATE serializes lookup, mutation and the canonical outcome fact.
// The retry ledger is its certified, rebuildable projection.
pub(super) const RECEIPTS: &str = crate::kernel::MCP_WRITE_RECEIPTS_DDL;

// Preserve the adapter's established fingerprint identity during replay and migration.
pub(super) use crate::kernel::mcp_write_receipts::{intent_fingerprint, stored_fingerprint};
/// The admission identity the current dispatch would fingerprint under:
/// the ambient app claim, plus the mint context exactly when the compound
/// envelope applies (minted-ID tool with an id_nonce while the feature is
/// enabled). Shared by [`dispatched_fingerprint`] and the replay seam so the
/// ambient selection cannot drift from the ordinary path.
pub(super) fn ambient_proposal_identity(
    tool: &str,
    request: &Value,
) -> Result<replay::ProposalIdentity> {
    // An explicit JSON null app counts as unset, matching from_original's
    // normalization so the two sides cannot disagree on it.
    let app = kernel::app_installs::dispatched_identity().filter(|app| !app.is_null());
    let mint_context = if matches!(tool, "create_record" | "attach_text" | "attach_from_url")
        && request.get("id_nonce").is_some()
        && minted_ids_enabled()
    {
        Some(crate::provenance::record_mint_context()?)
    } else {
        None
    };
    Ok(replay::ProposalIdentity { app, mint_context })
}

pub(super) fn dispatched_fingerprint(tool: &str, request: Value) -> Result<String> {
    // Thin wrapper: select the identity from the current dispatch, then
    // fingerprint purely; [`replay::proposal_fingerprint`] is the single
    // normalization path.
    let identity = ambient_proposal_identity(tool, &request)?;
    replay::proposal_fingerprint(tool, &request, &identity)
}

// Explicit server opt-in, matching the environment-selected v2/standby pilots.
pub(super) fn minted_ids_enabled() -> bool {
    #[cfg(test)]
    if let Ok(enabled) = MINTED_IDS_TEST.try_with(|enabled| *enabled) {
        return enabled;
    }
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("NATIVE_CE_V2_MINTED_RECORD_IDS").is_ok_and(|v| v == "1"))
}
#[cfg(test)]
tokio::task_local! { static MINTED_IDS_TEST: bool; }

fn mint_evidence(actor: &str, args: &Value, id_key: &str) -> Result<Option<Value>> {
    mint_evidence_in_context(actor, args, id_key, None)
}
fn mint_evidence_in_context(
    actor: &str,
    args: &Value,
    id_key: &str,
    captured: Option<&replay::FirstPartyCreateContext>,
) -> Result<Option<Value>> {
    if !minted_ids_enabled() {
        return Ok(None);
    }
    let id = optional_text(args, id_key)?;
    let nonce = optional_text(args, "id_nonce")?;
    if id.is_none() && nonce.is_none() {
        return Ok(None);
    }
    let principal = crate::record_id::qualified_principal(actor);
    let context = match captured {
        Some(context) => context.observed().to_owned(),
        None => crate::provenance::record_mint_context()?,
    };
    if !id
        .zip(nonce)
        .is_some_and(|(id, nonce)| crate::record_id::verify(&principal, &context, id, nonce))
    {
        return Err(invalid("invalid record id proof"));
    }
    Ok(Some(
        json!({"record_id_mint":{"version":1,"principal":principal,"context":context,"nonce":nonce}}),
    ))
}

async fn refuse_minted_occupancy(tx: &mut SqliteConnection, id: &str) -> Result<()> {
    kernel::mcp_write_receipts::fences::refuse_retired_on(tx, id, None).await?;
    let used: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id=? UNION ALL SELECT 1 FROM kernel_roots WHERE root_id=? UNION ALL SELECT 1 FROM kernel_principals WHERE principal_id=?)")
        .bind(id).bind(id).bind(id).fetch_one(&mut *tx).await?;
    if used {
        return Err(Error::conflict("id unavailable"));
    }
    Ok(())
}

async fn execute(db: &Db, actor: &str, tool: &str, args: Value) -> Result<Value> {
    if tool == "manage_named_views" {
        return Err(Error::auth(
            "named view operations require authenticated caller dispatch",
        ));
    }
    if tool == "create_many" {
        return create_many::execute(db, actor, args).await;
    }
    if tool == "manage_links" && args["action"] == "list" {
        return list_links(db, actor, args).await;
    }
    let mut tx = begin_write(db.write_pool()).await?;
    let receipt = execute_transaction(db, &mut tx, actor, tool, args, None).await?;
    db.commit_kernel_content(tx).await?;
    Ok(receipt)
}

async fn execute_transaction(
    db: &Db,
    tx: &mut Transaction<'_, Sqlite>,
    actor: &str,
    tool: &str,
    args: Value,
    context: Option<&mut crate::coedit::live::kernel_writes::KernelBodyWrite>,
) -> Result<Value> {
    execute_write_driver(
        db,
        WriteDriver::Ordinary {
            tx,
            tool,
            context,
            create_context: None,
        },
        actor,
        args,
    )
    .await
}

#[cfg(all(feature = "v2-kernel-probe", feature = "mcp-executor-prototype"))]
pub(crate) async fn execute_installed(
    db: &Db,
    caller: Caller,
    admission: WriteAdmission,
) -> Result<Value> {
    let original = admission.original();
    let actor = original.principal_id.clone();
    let args = original.arguments.clone();
    if original.operation == "update_record" {
        return execute_update_owned(db, &actor, &caller, args, Some(admission)).await;
    }
    let db = db.clone();
    crate::coedit::live::kernel_writes::owned_result(db.clone(), async move {
        let mut tx = begin_write(db.write_pool()).await?;
        if super::principal_on(&mut tx, &caller).await? != actor {
            return Err(Error::auth("installed writer caller binding changed"));
        }
        let original = admission.original();
        admission.recheck(&mut tx, &actor).await?;
        replay::admit_enrolled_node_on(&mut tx, &actor, original).await?;
        let receipt = if original.operation == "create_record" {
            let context = replay::FirstPartyCreateContext::for_enrolled_node()?;
            execute_captured_create_transaction(&db, &mut tx, &actor, args, &context).await?
        } else {
            execute_transaction(&db, &mut tx, &actor, &original.operation, args, None).await?
        };
        db.commit_kernel_content(tx).await?;
        Ok(receipt)
    })
    .await
}

async fn execute_captured_create_transaction(
    db: &Db,
    tx: &mut Transaction<'_, Sqlite>,
    actor: &str,
    args: Value,
    captured: &replay::FirstPartyCreateContext,
) -> Result<Value> {
    execute_write_driver(
        db,
        WriteDriver::Ordinary {
            tx,
            tool: "create_record",
            context: None,
            create_context: Some(captured),
        },
        actor,
        args,
    )
    .await
}

/// The connection-only variant cannot select any non-update tool. Ordinary
/// callers still own their real SQLx Transaction and old dispatcher surface.
enum WriteDriver<'a, 'conn> {
    Ordinary {
        tx: &'a mut Transaction<'conn, Sqlite>,
        tool: &'a str,
        context: Option<&'a mut crate::coedit::live::kernel_writes::KernelBodyWrite>,
        create_context: Option<&'a replay::FirstPartyCreateContext>,
    },
    Update {
        transaction: &'a mut crate::coedit::live::kernel_writes::KernelTransaction<
            crate::coedit::live::kernel_writes::KernelBodyWrite,
        >,
        caller: &'a Caller,
    },
}
impl WriteDriver<'_, '_> {
    fn connection(&mut self) -> &mut SqliteConnection {
        match self {
            Self::Ordinary { tx, .. } => tx,
            Self::Update { transaction, .. } => transaction.parts().0,
        }
    }
    fn live(&mut self) -> bool {
        match self {
            Self::Ordinary { context, .. } => context.as_ref().is_some_and(|owner| owner.is_live()),
            Self::Update { transaction, .. } => transaction.parts().1.is_live(),
        }
    }
}
async fn execute_update_connection(
    db: &Db,
    transaction: &mut crate::coedit::live::kernel_writes::KernelTransaction<
        crate::coedit::live::kernel_writes::KernelBodyWrite,
    >,
    caller: &Caller,
    actor: &str,
    args: Value,
) -> Result<Value> {
    execute_write_driver(
        db,
        WriteDriver::Update {
            transaction,
            caller,
        },
        actor,
        args,
    )
    .await
}

async fn execute_write_driver(
    db: &Db,
    mut driver: WriteDriver<'_, '_>,
    actor: &str,
    args: Value,
) -> Result<Value> {
    let tool = match &driver {
        WriteDriver::Ordinary { tool, .. } => *tool,
        WriteDriver::Update { .. } => "update_record",
    };
    let create_context = match &driver {
        WriteDriver::Ordinary { create_context, .. } => *create_context,
        _ => None,
    };
    // Pure proof verification precedes receipt and occupancy reads. Transport
    // identity resolution remains the ordinary authenticated admission boundary.
    let minted = if matches!(tool, "create_record" | "attach_text") {
        mint_evidence_in_context(
            actor,
            &args,
            if tool == "create_record" {
                "id"
            } else {
                "attachment_id"
            },
            create_context,
        )?
    } else {
        None
    };
    let can_publish_personal_app =
        matches!(&driver, WriteDriver::Update { caller, .. } if caller.can_update_personal_app());
    let live = driver.live();
    let tx = driver.connection();

    if tool == "update_record"
        && ["body", "body_set", "body_append", "body_replace"]
            .iter()
            .any(|k| args.get(*k).is_some())
    {
        let id = text(&args, "id")?;
        let record = phase(Stage::InitialView, view(tx, actor, id)).await?;
        if kernel::app_installs::is_artifact_on(tx, &record).await? {
            if !can_publish_personal_app {
                return Err(Error::auth(
                    "app source publication requires an eligible workspace member",
                ));
            }
            kernel::app_installs::sources::require_owner_on(tx, actor, id, None).await?;
        }
    }
    let key = optional_text(&args, "idempotency_key")?
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if key.is_some_and(|s| s.chars().count() > 200) {
        return Err(invalid("idempotency_key must be 1..200 characters"));
    }
    if tool == "attach_text" {
        text(&args, "text")?;
    }
    let request_json = match create_context {
        Some(context) => replay::proposal_fingerprint(tool, &args, &context.identity())?,
        None => dispatched_fingerprint(tool, args.clone())?,
    };
    if let Some(key) = key {
        kernel::mcp_write_receipts::fences::refuse_key_on(tx, actor, tool, key).await?;
    }
    // Current consent and source View are checked before success-receipt
    // lookup, on the same serialized snapshot that will perform the effects.
    kernel::app_installs::admit_dispatched_on(tx, actor).await?;
    sqlx::query(RECEIPTS).execute(&mut *tx).await?;
    if let Some(key) = key {
        let old: Option<(String,String)> = sqlx::query_as("SELECT request_json,receipt_json FROM kernel_mcp_write_receipts WHERE principal_id=? AND operation=? AND operation_key=?")
            .bind(actor).bind(tool).bind(key).fetch_optional(&mut *tx).await?;
        if let Some((old_request, receipt)) = old {
            if stored_fingerprint(tool, serde_json::from_str(&old_request)?)? != request_json {
                return Err(Error::conflict(
                    "idempotency_key reused for different request",
                ));
            }
            let receipt_raw = receipt;
            let receipt: Value = serde_json::from_str(&receipt_raw)?;
            // Replay does not confer access after revocation or a move.
            let id = if tool == "attach_text" {
                text(&receipt, "attachment_id")?
            } else {
                text(&receipt, "id")?
            };
            if tool == "attach_text" {
                kernel::kernel_require(tx, actor, text(&receipt, "record_id")?, Capability::Edit)
                    .await?;
                kernel::blobs::metadata(tx, actor, id).await?;
            }
            if tool == "update_record" && args.get("home_id").is_some() {
                kernel::kernel_require(tx, actor, id, Capability::Manage).await?;
                let home = crate::v1_import::resolve_home_on_connection(
                    tx,
                    actor,
                    receipt
                        .get("redirected_home")
                        .and_then(|r| r.get("applied"))
                        .and_then(Value::as_str)
                        .unwrap_or(text(&args, "home_id")?),
                )
                .await?;
                kernel::kernel_require(tx, actor, &home, Capability::Edit).await?;
            }
            let required = if tool == "archive_record" {
                Capability::Manage
            } else {
                Capability::Edit
            };
            // Comment creation authorizes on bearer View, never Edit: a
            // keyed retry re-proves the bearer below instead of Edit on
            // the comment. Updates and archives keep the Edit fence, so
            // replay confers nothing after revocation.
            let creation_is_comment =
                tool == "create_record" && kernel::comments_v2::is_comment_on(tx, id).await?;
            if !creation_is_comment {
                kernel::kernel_require(tx, actor, id, required).await?;
            }
            for target in receipt["link_targets"].as_array().into_iter().flatten() {
                kernel::kernel_require(tx, actor, target.as_str().unwrap(), Capability::View)
                    .await?;
            }
            // Compact legacy receipts only after current-policy authorization.
            let mut replay_acts = ActAllocation::new();
            kernel::mcp_write_receipts::record_on(
                db,
                tx,
                &mut replay_acts,
                kernel::mcp_write_receipts::Outcome {
                    principal: actor,
                    operation: tool,
                    key,
                    request: &request_json,
                    receipt: &receipt_raw,
                },
            )
            .await?;
            return Ok(receipt);
        }
    }
    if minted.is_some() {
        let id = text(
            &args,
            if tool == "attach_text" {
                "attachment_id"
            } else {
                "id"
            },
        )?;
        refuse_minted_occupancy(tx, id).await?;
    }
    if key.is_some() && live {
        return Err(Error::engine(
            "new keyed kernel body/scope writes are refused while live; replay remains available",
        ));
    }
    let mut acts = ActAllocation::new();
    use sha2::{Digest, Sha256};
    let request_digest = hex::encode(Sha256::digest(request_json.as_bytes()));
    let pending = kernel::app_installs::start_app_action_in(
        db,
        tx,
        actor,
        tool,
        request_digest.clone(),
        optional_text(&args, "reason")?.map(str::to_owned),
        &mut acts,
    )
    .await?;
    let mut receipt = match &mut driver {
        WriteDriver::Update {
            transaction,
            caller,
        } => {
            let (tx, context) = transaction.parts();
            let binding = if context.is_live() {
                Some(
                    kernel::app_installs::bind_update_action_on(
                        tx,
                        pending.as_deref(),
                        caller,
                        actor,
                        &args,
                        &request_digest,
                        &acts,
                    )
                    .await?,
                )
            } else {
                None
            };
            update_with_context(
                db,
                tx,
                &mut acts,
                actor,
                &args,
                None,
                Some(context),
                binding,
                can_publish_personal_app,
                None,
            )
            .await?
        }
        WriteDriver::Ordinary { tx, context, .. } => match tool {
            "attach_text" => attach_text(db, tx, &mut acts, actor, &args).await?,
            "create_record" => {
                create_with_details(db, tx, &mut acts, actor, &args, None, None, create_context)
                    .await?
            }
            "update_record" => {
                update_with_context(
                    db,
                    tx,
                    &mut acts,
                    actor,
                    &args,
                    None,
                    context.take(),
                    None,
                    false,
                    None,
                )
                .await?
            }
            "manage_links" => mutate_link(db, tx, &mut acts, actor, &args).await?,
            "archive_record" => archive(db, tx, &mut acts, actor, &args).await?,
            _ => unreachable!(),
        },
    };
    let tx = driver.connection();
    if let Some(attribution) =
        kernel::app_installs::finish_app_action_in(db, tx, actor, pending, &mut acts).await?
    {
        receipt["app_attribution"] = attribution;
    }
    if let Some(key) = key {
        kernel::mcp_write_receipts::record_on(
            db,
            tx,
            &mut acts,
            kernel::mcp_write_receipts::Outcome {
                principal: actor,
                operation: tool,
                key,
                request: &request_json,
                receipt: &serde_json::to_string(&receipt)?,
            },
        )
        .await?;
    }
    Ok(receipt)
}

struct OwnedUpdateDisposition {
    // A separately durable effect; dropping a waiter/result cannot undo it.
    preflush: Option<crate::coedit::live::Versioned>,
    outer: Result<Value>,
}

async fn execute_update_owned(
    db: &Db,
    actor: &str,
    caller: &crate::mcp::Caller,
    args: Value,
    #[cfg(all(feature = "v2-kernel-probe", feature = "mcp-executor-prototype"))] installed: Option<
        WriteAdmission,
    >,
) -> Result<Value> {
    use crate::coedit::live::kernel_writes::{
        owned_result, KernelBodyWrite, KernelTransaction, KernelWriteMode,
    };
    validate_update_shape(&args)?;
    #[cfg(all(feature = "v2-kernel-probe", feature = "mcp-executor-prototype"))]
    if installed.is_some()
        && optional_text(&args, "idempotency_key")?.is_none_or(|key| key.trim().is_empty())
    {
        return Err(invalid("installed writes require an original key"));
    }
    let (db, actor, caller) = (db.clone(), actor.to_owned(), caller.clone());
    #[cfg(test)]
    let fixture_owner =
        crate::coedit::live::kernel_writes::capture_writer_fixture_owner_for_test(&db);
    let disposition = owned_result(
        db.clone(),
        super::write_diagnostics::update_record(async move {
            let id = text(&args, "id")?;
            let body = ["body", "body_set", "body_append", "body_replace"]
                .iter()
                .any(|key| args.get(*key).is_some());
            let scope = args.get("home_id").is_some()
                || args
                    .get("facets")
                    .and_then(Value::as_object)
                    .is_some_and(|facets| facets.contains_key("runtime"));
            let keyed =
                optional_text(&args, "idempotency_key")?.is_some_and(|key| !key.trim().is_empty());
            let mode = if !body && !scope {
                KernelWriteMode::Metadata
            } else if keyed {
                KernelWriteMode::ReplayOnly
            } else if scope {
                KernelWriteMode::RefuseLive
            } else {
                KernelWriteMode::RouteBody
            };
            let ownership = phase(Stage::Ownership, async {
                #[cfg(test)]
                let result = KernelBodyWrite::acquire_fixture_owned_update_for_test(
                    &db,
                    &caller,
                    Some(id),
                    mode,
                    fixture_owner,
                )
                .await;
                #[cfg(not(test))]
                let result = KernelBodyWrite::acquire(&db, &caller, Some(id), mode).await;
                result
            })
            .await?;
            let (ownership, preflush) = if mode == KernelWriteMode::RouteBody {
                phase(
                    Stage::Preflush,
                    ownership.flush(&caller, "saved before a routed kernel write"),
                )
                .await?
            } else {
                (ownership, None)
            };
            let outer = async {
                #[cfg(test)]
                if mode == KernelWriteMode::RouteBody {
                    crate::coedit::live::kernel_writes::test_checkpoint(
                        &db,
                        crate::coedit::live::kernel_writes::TestStage::AfterFlush,
                    )
                    .await?;
                }
                let mut transaction = phase(
                    Stage::Begin,
                    KernelTransaction::begin(&db, ownership, KernelBodyWrite::quarantine),
                )
                .await?;
                let result = async {
                    {
                        let (tx, _) = transaction.parts();
                        let current = super::principal_on(tx, &caller).await?;
                        if current != actor {
                            return Err(Error::auth("kernel writer caller binding changed"));
                        }
                        if caller.verified_release_append() {
                            super::release_append::validate_on(tx, &actor, &args).await?;
                        }
                        #[cfg(all(
                            feature = "v2-kernel-probe",
                            feature = "mcp-executor-prototype"
                        ))]
                        if let Some(installed) = &installed {
                            installed.recheck(tx, &actor).await?;
                            replay::admit_enrolled_node_on(tx, &actor, installed.original())
                                .await?;
                        }
                    }
                    let receipt = phase(
                        Stage::Mutation,
                        execute_update_connection(&db, &mut transaction, &caller, &actor, args),
                    )
                    .await?;
                    #[cfg(test)]
                    crate::coedit::live::kernel_writes::test_checkpoint(
                        &db,
                        crate::coedit::live::kernel_writes::TestStage::AfterMutation,
                    )
                    .await?;
                    let (tx, ownership) = transaction.parts();
                    phase(Stage::Validate, ownership.validate_in(tx)).await?;
                    Ok::<_, Error>(receipt)
                }
                .await;
                let receipt = match result {
                    Ok(receipt) => receipt,
                    Err(error) => return Err(transaction.rollback(error).await),
                };
                let mut ownership = phase(Stage::Commit, transaction.commit()).await?;
                ownership.install_committed()?;
                Ok(receipt)
            }
            .await;
            Ok(OwnedUpdateDisposition { preflush, outer })
        }),
    )
    .await?;
    // This preserves public Result<Value>; a known preflush remains separately
    // true in durable history even when outer is Err or delivery is cancelled.
    let OwnedUpdateDisposition {
        preflush: _known_preflush,
        outer,
    } = disposition;
    outer
}

fn validate_update_shape(args: &Value) -> Result<()> {
    allowed(
        args,
        &[
            "id",
            "home_id",
            "name",
            "summary",
            "lifecycle",
            "persistence",
            "maturity",
            "body",
            "body_set",
            "body_append",
            "body_replace",
            "if_body_digest",
            "if_unmodified_since",
            "if_policy_revision",
            "sources",
            "facets",
            "links",
            "reason",
            "response_mode",
            "idempotency_key",
        ],
    )?;
    text(args, "id")?;
    super::source_basis::validate_input(args.get("sources"), "update_record")?;
    let body_ops = ["body", "body_set", "body_append", "body_replace"]
        .iter()
        .filter(|key| args.get(**key).is_some())
        .count();
    if body_ops > 1 {
        return Err(invalid("use exactly one body operation"));
    }
    for field in [
        "body",
        "body_set",
        "name",
        "summary",
        "lifecycle",
        "home_id",
        "if_body_digest",
        "if_unmodified_since",
        "if_policy_revision",
        "reason",
        "idempotency_key",
    ] {
        optional_text(args, field)?;
    }
    if args.get("body_append").is_some() {
        text(args, "body_append")?;
    }
    if let Some(replacements) = args.get("body_replace") {
        let _: Vec<crate::mcp::tools::lifecycle::BodyReplace> =
            parse("update_record.body_replace", replacements.clone())?;
    }
    if let Some(key) = optional_text(args, "idempotency_key")? {
        if key.trim().chars().count() > 200 {
            return Err(invalid("idempotency_key must be 1..200 characters"));
        }
    }
    if let Some(facets) = args.get("facets").filter(|value| !value.is_null()) {
        object(facets)?;
    }
    if let Some(links) = args.get("links").filter(|value| !value.is_null()) {
        for link in links
            .as_array()
            .ok_or_else(|| invalid("links must be an array"))?
        {
            allowed(link, &["target_id", "relationship", "note"])?;
            text(link, "target_id")?;
            text(link, "relationship")?;
            optional_text(link, "note")?;
        }
    }
    if let Some(persistence) = args.get("persistence") {
        if !matches!(persistence.as_str(), Some("enduring" | "occurrent")) {
            return Err(invalid(
                "persistence must be enduring or occurrent; cannot clear persistence",
            ));
        }
    }
    optional_text(args, "maturity")?;
    if let Some(expected) = optional_text(args, "if_unmodified_since")? {
        chrono::DateTime::parse_from_rfc3339(expected)
            .map_err(|_| invalid("if_unmodified_since must be RFC3339"))?;
    }
    validate_lifecycle(args)?;
    Ok(())
}

pub(super) async fn event(
    db: &Db,
    tx: &mut SqliteConnection,
    acts: &mut ActAllocation,
    actor: &str,
    id: &str,
    kind: &str,
    payload: Value,
) -> Result<()> {
    // Callers must authorize before entering a lane: create_input_in checks
    // home Edit; update uses record_edit (Edit + CAS); archive requires Manage.
    // Keep that order when composing lanes. append_in also runs kernel admission.
    crate::store::append_on(
        db,
        tx,
        AppendSpec {
            record_id: id.into(),
            event_type: kind.into(),
            payload,
            actor: Some(actor.into()),
        },
        acts,
    )
    .await?;
    Ok(())
}
async fn view(
    tx: &mut SqliteConnection,
    actor: &str,
    id: &str,
) -> Result<kernel::KernelRecordView> {
    // Comment visibility derives through the bearer chain inside the kernel
    // capability check; writes still authorize per lane below.
    match kernel::read_record_on(tx, actor, id).await? {
        Some(record) => Ok(record),
        None => match kernel::app_scope_direct_refusal_on(tx, actor, id, Capability::View).await? {
            Some(error) => Err(error),
            None => Err(Error::engine(kernel::HIDDEN_OR_MISSING)),
        },
    }
}
// Mint a globally unambiguous UUID prefix, including hidden records and
// imported exact-prefix identities. Saturated scans fall back to the full id.
pub(crate) async fn short_reference(tx: &mut SqliteConnection, id: &str) -> Result<Option<String>> {
    let Ok(uuid) = uuid::Uuid::parse_str(id) else {
        return Ok(None);
    };
    if uuid.to_string() != id {
        return Ok(None);
    }
    let hex = uuid.simple().to_string();
    let candidates: Vec<String> =
        sqlx::query_scalar("SELECT id FROM kernel_records WHERE id LIKE ? ORDER BY id LIMIT 32")
            .bind(format!("{}%", &hex[..7]))
            .fetch_all(&mut *tx)
            .await?;
    if candidates.len() >= 32 {
        return Ok(None);
    }
    let mut length = 7;
    for other in candidates.iter().filter(|other| other.as_str() != id) {
        let other = other.replace('-', "");
        let shared = hex
            .bytes()
            .zip(other.bytes())
            .take_while(|(a, b)| a == b)
            .count();
        length = length.max(shared + 1);
    }
    Ok((length < 32).then(|| hex[..length].to_owned()))
}

async fn receipt(
    tx: &mut SqliteConnection,
    actor: &str,
    id: &str,
    effect: &str,
    previous: Option<&kernel::KernelRecordView>,
    targets: Vec<String>,
) -> Result<Value> {
    let current = view(tx, actor, id).await?;
    let display_reference = short_reference(tx, id).await?;
    let primary_type: Option<String> =
        sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    let (record_type, kind) = super::v1_type_and_kind(
        current.family.as_deref(),
        current.pin.as_ref().map(|p| p.version),
        primary_type.as_deref(),
        current.kind.as_deref(),
        &current.fields,
    );

    let updated_at = kernel::record_metadata::updated_at_on(tx, id).await?;
    let changed = effect != "unchanged";
    let mut result = json!({"id":id, "changed":changed, "short_ref":display_reference, "display_reference":display_reference, "effect":effect,
        "name":current.fields.get("title"), "type":record_type, "kind":kind,
        "lifecycle":current.fields.get("lifecycle"), "archived":current.archived, "body_digest":super::super::tools::lifecycle::body_digest(current.body.as_deref()),
        "version":format!("rec:{}", current.revision), "record_version":format!("rec:{}", current.revision), "updated_at":updated_at,
        "previous_seq":previous.map(|p| p.revision),
        "previous_record_version":previous.map(|p| format!("rec:{}",p.revision)),
        "previous_body_digest":previous.map(|p| super::super::tools::lifecycle::body_digest(p.body.as_deref())),
        "link_targets":targets, "kernel_v2":{"atomic":true}});
    if changed {
        // BEGIN IMMEDIATE excludes other writers, and each changed caller has
        // appended at least one event. The last row therefore belongs to this
        // operation (possibly a provider aggregate). No-ops never use this row.
        let (seq, event_id, event_type, record_id, created_at, act): (
            i64,
            String,
            String,
            String,
            String,
            Option<i64>,
        ) = sqlx::query_as(
            "SELECT seq,id,type,record_id,created_at,act FROM content_events ORDER BY seq DESC LIMIT 1",
        )
        .fetch_one(&mut *tx)
        .await?;
        result["act"] = json!(act);
        result["write_receipt"] = json!({"kind":"kernel_content_event","event":{"seq":seq,"event_id":event_id,"event_type":event_type,"record_id":record_id,"created_at":created_at}});
    }
    Ok(result)
}

async fn archive(
    db: &Db,
    tx: &mut SqliteConnection,
    acts: &mut ActAllocation,
    actor: &str,
    args: &Value,
) -> Result<Value> {
    allowed(args, &["id", "archived", "reason", "idempotency_key"])?;
    let id = text(args, "id")?;
    if text(args, "reason")?.trim().is_empty() {
        return Err(invalid("archive_record requires a nonblank reason"));
    }
    let archived = match args.get("archived") {
        None | Some(Value::Null) => true,
        Some(Value::Bool(value)) => *value,
        _ => return Err(invalid("archived must be a boolean")),
    };
    kernel::kernel_require(tx, actor, id, Capability::Manage).await?;
    let previous = view(tx, actor, id).await?;
    let changed = previous.archived != archived;
    let mut result = json!({"id":id, "archived":archived, "changed":changed});
    if changed {
        kernel::hq::record_edit(tx, actor, id, Some(previous.revision)).await?;
        event(
            db,
            tx,
            acts,
            actor,
            id,
            "kernel.archive_changed.v1",
            json!({"archived":archived}),
        )
        .await?;
        result["act"] = json!(acts.get());
    }
    // As in v1, a keyed no-op pins no record position in its receipt.
    if changed || optional_text(args, "idempotency_key")?.is_none_or(|key| key.trim().is_empty()) {
        result["previous_seq"] = json!(previous.revision);
    }
    Ok(result)
}

fn validate_lifecycle(args: &Value) -> Result<()> {
    if optional_text(args, "lifecycle")? == Some("archived") {
        return Err(invalid(
            "'archived' is not a lifecycle value; archive and restore via the archive_record tool",
        ));
    }
    Ok(())
}

async fn metadata_patch(
    db: &Db,
    tx: &mut SqliteConnection,
    acts: &mut ActAllocation,
    actor: &str,
    id: &str,
    args: &Value,
) -> Result<()> {
    metadata_patch_with_basis(db, tx, acts, actor, id, args, &mut None).await
}

async fn metadata_patch_with_basis(
    db: &Db,
    tx: &mut SqliteConnection,
    acts: &mut ActAllocation,
    actor: &str,
    id: &str,
    args: &Value,
    basis: &mut Option<Value>,
) -> Result<()> {
    let current = kernel::record_metadata::read_on(tx, id).await?;
    let mut patch = Map::new();
    if let Some(p) = args.get("persistence") {
        if !matches!(p.as_str(), Some("enduring" | "occurrent")) {
            return Err(invalid(
                "persistence must be enduring or occurrent; cannot clear persistence",
            ));
        }
        if p.as_str() != Some(&current.persistence) {
            patch.insert("persistence".into(), p.clone());
        }
    }
    if let Some(m) = args.get("maturity") {
        optional_text(args, "maturity")?;
        if m != &serde_json::to_value(&current.maturity)? {
            patch.insert("maturity".into(), m.clone());
        }
    }
    if !patch.is_empty() {
        if let Some(basis) = basis.take() {
            patch.insert("basis".into(), basis);
        }
        event(
            db,
            tx,
            acts,
            actor,
            id,
            "kernel.metadata_set.v1",
            patch.into(),
        )
        .await?;
    }
    Ok(())
}

pub(super) async fn create(
    db: &Db,
    tx: &mut Transaction<'_, Sqlite>,
    acts: &mut ActAllocation,
    actor: &str,
    args: &Value,
) -> Result<Value> {
    create_with_message(db, tx, acts, actor, args, None).await
}
pub(super) async fn create_with_origin(
    db: &Db,
    tx: &mut Transaction<'_, Sqlite>,
    acts: &mut ActAllocation,
    actor: &str,
    args: &Value,
    origin: Value,
) -> Result<Value> {
    create_with_details(db, tx, acts, actor, args, None, Some(origin), None).await
}
pub(super) async fn create_with_message(
    db: &Db,
    tx: &mut Transaction<'_, Sqlite>,
    acts: &mut ActAllocation,
    actor: &str,
    args: &Value,
    message: Option<&kernel::MessageState>,
) -> Result<Value> {
    create_with_details(db, tx, acts, actor, args, message, None, None).await
}

#[allow(clippy::too_many_arguments)]
async fn create_with_details(
    db: &Db,
    tx: &mut Transaction<'_, Sqlite>,
    acts: &mut ActAllocation,
    actor: &str,
    args: &Value,
    message: Option<&kernel::MessageState>,
    origin: Option<Value>,
    captured: Option<&replay::FirstPartyCreateContext>,
) -> Result<Value> {
    allowed(
        args,
        &[
            "type",
            "id",
            "id_nonce",
            "kind",
            "name",
            "summary",
            "body",
            "lifecycle",
            "persistence",
            "maturity",
            "facets",
            "home_id",
            "links",
            "target",
            "reason",
            "response_mode",
            "confirm",
            "idempotency_key",
            "access_policy",
            "sources",
        ],
    )?;
    if minted_ids_enabled()
        && origin.is_some()
        && ["id", "id_nonce"]
            .iter()
            .any(|key| args.get(*key).is_some())
    {
        return Err(invalid(
            "caller record IDs are not supported for origin-bearing creates",
        ));
    }
    let mint = if message.is_none() {
        mint_evidence_in_context(actor, args, "id", captured)?
    } else {
        None
    };
    if mint.is_some() {
        refuse_minted_occupancy(tx, text(args, "id")?).await?;
    }
    let origin = match mint {
        Some(mint) => Some(mint),
        None => origin,
    };
    let typ = text(args, "type")?;
    let redirected_home =
        crate::mcp::tools::redirects_root_filing(Some(typ), optional_text(args, "home_id")?);
    let raw_kind = text(args, "kind")?;
    if typ == "Configuration" && raw_kind == "saved_tab" {
        return Err(invalid("saved tabs require manage_saved_tabs.create"));
    }
    let canonical_kind = kernel::v1_state::interpreter_on(tx, actor)
        .await?
        .canonical_imported_kind(typ, raw_kind);
    let kind = canonical_kind.as_str();
    if typ.trim().is_empty() || kind.trim().is_empty() {
        return Err(invalid("type and kind must not be empty"));
    }
    if typ == "Message" && message.is_none() {
        return Err(invalid("use manage_messages.send to seal the audience"));
    }
    if message.is_none() && args.get("id").is_some() && !minted_ids_enabled() {
        return Err(invalid("id is only supported for messaging sends"));
    }
    if typ == "Document" && kind == "attachment" {
        return Err(invalid(
            "create_record: use attach_text to create Document/attachment records",
        ));
    }
    validate_lifecycle(args)?;
    let comment = super::comments::is_comment_type(typ, kind);
    let account_only = match optional_text(args, "access_policy")? {
        None => false,
        Some("account_only") => true,
        Some(_) => {
            return Err(invalid(
                "access_policy must be the single literal account_only",
            ))
        }
    };
    if account_only && (typ == "Message" || typ == "Annotation" || message.is_some()) {
        return Err(invalid("access_policy is not supported for derived records or Messages; the bearer or audience owns the policy boundary"));
    }
    if account_only {
        let account: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id=? AND kind='account')")
            .bind(actor).fetch_one(&mut **tx).await?;
        if !account {
            return Err(invalid(
                "access_policy requires an authenticated account principal",
            ));
        }
    }
    let basis = super::source_basis::resolve(tx, actor, args.get("sources")).await?;
    let declared_sources = basis
        .as_ref()
        .map(|b| b["sources"].as_array().unwrap().len());

    if !comment && args.get("target").is_some_and(|target| !target.is_null()) {
        return Err(Error::engine(
            "create_record: target is valid only for Annotation kind:citation or a comment root",
        ));
    }
    let annotation_bearer = if typ == "Annotation" && !comment {
        let links = args
            .get("links")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("Annotation requires exactly one part_of bearer"))?;
        let bearers: Vec<&str> = links
            .iter()
            .filter(|l| l.get("relationship").and_then(Value::as_str) == Some("part_of"))
            .map(|l| text(l, "target_id"))
            .collect::<Result<_>>()?;
        let [bearer] = bearers.as_slice() else {
            return Err(invalid("Annotation requires exactly one part_of bearer"));
        };
        kernel::kernel_require(tx, actor, bearer, Capability::View).await?;
        Some((*bearer).to_owned())
    } else {
        None
    };
    let plan = if comment {
        Some(
            super::comments::prepare_create(
                tx,
                actor,
                args,
                optional_text(args, "body")?,
                optional_text(args, "lifecycle")?,
                optional_text(args, "summary")?,
            )
            .await?,
        )
    } else {
        None
    };
    let lifecycle = optional_text(args, "lifecycle")?
        .or_else(|| (typ == "WorkItem" && matches!(kind, "task" | "epic")).then_some("open"));
    let carrier = v1_compat::v1_carrier_for(typ, kind);
    let mut fields = v1_compat::compat_fields(
        typ,
        kind,
        optional_text(args, "name")?,
        optional_text(args, "summary")?,
        lifecycle,
    );
    if let Some(plan) = &plan {
        // Name the root state instead of leaving it to absence: a root
        // created with no lifecycle is an FYI, so it stores `informational`.
        // Replies keep their null — thread state lives on the root.
        if let Some(lifecycle) = &plan.lifecycle {
            fields.insert("lifecycle".into(), lifecycle.clone().into());
        }
    }
    if carrier == v1_compat::V1Carrier::DocumentNote {
        fields.remove("v1_type");
        fields.remove("v1_kind");
    }
    // A record-local policy home is authority, not its v1 filing folder.
    // Explicit annotation homes validate against the bearer's logical filing
    // home, then retain the bearer's actual policy scope.
    let annotation_placement = if let Some(bearer) = &annotation_bearer {
        let scope = view(tx, actor, bearer).await?.home_id;
        let filing = kernel::v1_state::lifecycle_bearer_on(tx, &scope, Some(bearer)).await?;
        Some((scope, filing))
    } else {
        None
    };
    let home = match &plan {
        // Comments validate their bearer/home through the thread plan.
        Some(plan) => plan.home.clone(),
        None => {
            let requested = if redirected_home {
                crate::schema::UNFILED_RECORD_ID
            } else {
                optional_text(args, "home_id")?.unwrap_or(crate::events::KERNEL_ROOT_ID)
            };
            let selector = annotation_placement
                .as_ref()
                .filter(|(scope, _)| requested == scope)
                .map(|(_, filing)| filing.as_str())
                .unwrap_or(requested);
            kernel::folder_home_in(db, tx, acts, actor, selector).await?;
            crate::v1_import::resolve_home_on(tx, actor, selector).await?
        }
    };
    let home = if let Some((scope, filing)) = annotation_placement {
        if args.get("home_id").is_some() {
            let expected = crate::v1_import::resolve_home_on(tx, actor, &filing).await?;
            if home != expected {
                return Err(invalid("Annotation home must match its bearer"));
            }
        }
        scope
    } else {
        home
    };
    let bearer = kernel::v1_state::lifecycle_bearer_on(tx, &home, None).await?;
    kernel::v1_state::interpreter_on(tx, actor)
        .await?
        .validate_imported_write(
            typ,
            kind,
            Some(&bearer),
            fields.get("lifecycle").and_then(Value::as_str),
        )?;
    let raw = serde_json::to_string(&fields)?;
    let id = match &plan {
        Some(plan) => {
            kernel::comments_v2::create_comment_in(
                db,
                tx,
                acts,
                actor,
                carrier.family(),
                carrier.kind(),
                kernel::FieldInput::Raw(&raw),
                &home,
                &plan.bearer,
                optional_text(args, "id")?,
                origin.clone(),
                basis.clone(),
            )
            .await?
        }
        None => {
            kernel::create_input_admitted_in(
                db,
                tx,
                acts,
                actor,
                carrier.family(),
                carrier.kind(),
                kernel::FieldInput::Raw(&raw),
                &home,
                None,
                true,
                optional_text(args, "id")?,
                origin,
                basis,
            )
            .await?
        }
    };
    if let Some(message) = message {
        event(
            db,
            tx,
            acts,
            actor,
            &id,
            kernel::messaging::CREATED,
            serde_json::to_value(message)?,
        )
        .await?;
    }
    if account_only {
        kernel::account_only_record_in(db, tx, acts, actor, &id).await?;
    }
    if typ == "Collection" && kind == "folder" {
        kernel::folder_home_in(db, tx, acts, actor, &id).await?;
    }
    metadata_patch(db, tx, acts, actor, &id, args).await?;
    if let Some(body) = optional_text(args, "body")? {
        event(
            db,
            tx,
            acts,
            actor,
            &id,
            "kernel.body_set.v1",
            json!({"body":body}),
        )
        .await?;
    }
    facets(
        db,
        tx,
        acts,
        actor,
        &id,
        args.get("facets"),
        "create_record",
    )
    .await?;
    let targets = new_links(
        db,
        tx,
        acts,
        actor,
        &id,
        args.get("links"),
        plan.as_ref()
            .map(|plan| plan.bearer.as_str())
            .or(annotation_bearer.as_deref()),
    )
    .await?;
    if let Some(plan) = plan {
        // Anchor before the bearer link: it reads the projected body while
        // the chain is still incomplete, fenced by creation. The link
        // commits last and completes the thread.
        if let Some(anchor) = plan.anchor {
            kernel::comments_v2::set_anchor_in(db, tx, acts, actor, &id, anchor).await?;
        }
        kernel::comments_v2::append_bearer_link_in(db, tx, acts, actor, &id, &plan.bearer).await?;
    }
    if let Some(bearer) = annotation_bearer {
        kernel::comments_v2::append_bearer_link_in(db, tx, acts, actor, &id, &bearer).await?;
    }
    let mut result = receipt(tx, actor, &id, "created", None, targets).await?;
    if redirected_home {
        crate::mcp::tools::disclose_root_filing(&mut result);
    }
    if let Some(feedback) =
        super::super::tools::lifecycle::declared_basis_feedback(declared_sources)
    {
        result["basis"] = feedback;
    }
    Ok(result)
}

pub(crate) async fn update(
    db: &Db,
    tx: &mut Transaction<'_, Sqlite>,
    acts: &mut ActAllocation,
    actor: &str,
    args: &Value,
) -> Result<Value> {
    update_with_origin(db, tx, acts, actor, args, None).await
}

pub(super) async fn update_with_origin(
    db: &Db,
    tx: &mut Transaction<'_, Sqlite>,
    acts: &mut ActAllocation,
    actor: &str,
    args: &Value,
    origin: Option<Value>,
) -> Result<Value> {
    update_with_context(db, tx, acts, actor, args, origin, None, None, false, None).await
}

#[allow(clippy::too_many_arguments)]
async fn update_with_context(
    db: &Db,
    tx: &mut SqliteConnection,
    acts: &mut ActAllocation,
    actor: &str,
    args: &Value,
    origin: Option<Value>,
    context: Option<&mut crate::coedit::live::kernel_writes::KernelBodyWrite>,
    binding: Option<kernel::app_installs::RoutedActionBinding<'_>>,
    can_publish_personal_app: bool,
    resolved_basis: Option<Option<Value>>,
) -> Result<Value> {
    if kernel::messaging::is_message(tx, text(args, "id")?).await? {
        return Err(invalid(
            "sealed Message content is immutable; send a reply or correction",
        ));
    }
    allowed(
        args,
        &[
            "id",
            "home_id",
            "name",
            "summary",
            "lifecycle",
            "persistence",
            "maturity",
            "body",
            "body_set",
            "body_append",
            "body_replace",
            "if_body_digest",
            "if_unmodified_since",
            "if_policy_revision",
            "sources",
            "facets",
            "links",
            "reason",
            "response_mode",
            "idempotency_key",
        ],
    )?;
    let id = text(args, "id")?;
    // Read before authorizing: comments authorize below through the
    // terminal bearer (with v1's insufficient-capability refusal when the
    // thread is visible), while every other record keeps the Edit fence.
    // Hidden records read as missing either way.
    let previous = phase(Stage::PreviousView, view(tx, actor, id)).await?;
    // Resolve the public type on the same snapshot as the move. Preserve the
    // original request for the command fingerprint and retry receipt.
    let redirected_home = if optional_text(args, "home_id")? == Some(crate::schema::ROOT_RECORD_ID)
    {
        let primary_type: Option<String> =
            sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
        let (typ, _) = super::v1_type_and_kind(
            previous.family.as_deref(),
            previous.pin.as_ref().map(|p| p.version),
            primary_type.as_deref(),
            previous.kind.as_deref(),
            &previous.fields,
        );
        crate::mcp::tools::redirects_root_filing(typ, Some(crate::schema::ROOT_RECORD_ID))
    } else {
        false
    };

    if let Some(basis) = context.as_ref().and_then(|owner| owner.live_body()) {
        // Routed body operations start only after their own dirty cut, with
        // ops held. Canonical and live basis must now agree exactly.
        if previous.body.as_deref().unwrap_or("") != basis && args.get("idempotency_key").is_none()
        {
            return Err(Error::conflict(
                "kernel live basis disagrees with committed body",
            ));
        }
    }
    // App admission may already own the act. Only events appended by this
    // update count as a data change; allocating attribution is not a save.
    let before_event_seq: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM main.content_events")
            .fetch_one(&mut *tx)
            .await?;
    if super::comments::record_is_comment(&previous) {
        // Resolve and every other comment write need Edit on the thread,
        // which derives from the terminal bearer as v1 resolves it. A
        // viewer who can see the thread gets v1's insufficient-capability
        // refusal instead of the missing-or-hidden one.
        let capability = kernel::kernel_effective_capability_on(tx, actor, id).await?;
        if !capability.allows(Capability::Edit) {
            if capability.allows(Capability::View) {
                return Err(Error::engine(format!(
                    "update_record: record {id} requires edit capability; caller has {} capability",
                    capability.as_policy_str().unwrap_or("none")
                )));
            }
            return Err(Error::engine(kernel::HIDDEN_OR_MISSING));
        }
    } else {
        kernel::kernel_require(tx, actor, id, Capability::Edit).await?;
    }
    kernel::policy_read::assert_revision_on(
        tx,
        actor,
        id,
        optional_text(args, "if_policy_revision")?,
    )
    .await?;
    if args.get("home_id").is_some_and(Value::is_null) {
        return Err(invalid(
            "home_id must name a destination; it cannot be cleared",
        ));
    }
    let move_home = if let Some(requested) = optional_text(args, "home_id")? {
        kernel::kernel_require(tx, actor, id, Capability::Manage).await?;
        if super::comments::record_is_comment(&previous) {
            return Err(invalid("a comment moves only with its terminal bearer"));
        }
        let requested = if redirected_home {
            crate::schema::UNFILED_RECORD_ID
        } else {
            requested
        };
        kernel::folder_home_in(db, tx, acts, actor, requested).await?;
        let home = crate::v1_import::resolve_home_on_connection(tx, actor, requested).await?;
        kernel::kernel_require(tx, actor, &home, Capability::Edit).await?;
        // A native home ID must not bypass the liveness/Edit checks on its
        // imported logical folder.
        let logical: Option<String> = sqlx::query_scalar("SELECT json_extract(payload,'$.source_record_id') FROM content_events WHERE record_id=? AND type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(payload,'$.source_record_id') IS NOT NULL ORDER BY seq LIMIT 1")
            .bind(&home).fetch_optional(&mut *tx).await?;
        let destination_id = logical.as_deref().unwrap_or(requested);
        if destination_id != crate::events::KERNEL_ROOT_ID
            && destination_id != crate::schema::ROOT_RECORD_ID
        {
            let native: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id=?)")
                    .bind(destination_id)
                    .fetch_one(&mut *tx)
                    .await?;
            if !native {
                let destination = view(tx, actor, destination_id).await?;
                if destination.archived
                    || destination.fields.get("v1_type").and_then(Value::as_str)
                        != Some("Collection")
                    || destination.fields.get("v1_kind").and_then(Value::as_str) != Some("folder")
                {
                    return Err(invalid("destination must be a live unarchived folder"));
                }
                kernel::kernel_require(tx, actor, destination_id, Capability::Edit).await?;
            }
        }
        Some(home)
    } else {
        None
    };
    let current_digest = super::super::tools::lifecycle::body_digest(previous.body.as_deref());
    if let Some(expected) = optional_text(args, "if_body_digest")? {
        if expected != current_digest {
            return Err(Error::conflict("stale if_body_digest; nothing written"));
        }
    }
    if let Some(expected) = optional_text(args, "if_unmodified_since")? {
        let expected = chrono::DateTime::parse_from_rfc3339(expected)
            .map_err(|_| invalid("if_unmodified_since must be RFC3339"))?;
        let updated = kernel::record_metadata::updated_at_on(tx, id).await?;
        let guard_updated = context
            .as_ref()
            .map(|owner| owner.guard_updated_at(&updated))
            .unwrap_or(&updated);
        let updated = chrono::DateTime::parse_from_rfc3339(guard_updated)
            .map_err(|_| invalid("invalid kernel timestamp"))?;
        if updated != expected {
            return Err(Error::conflict(
                "stale if_unmodified_since; nothing written",
            ));
        }
    }
    validate_lifecycle(args)?;
    if args.get("lifecycle").is_some() || move_home.is_some() {
        let primary_type: Option<String> =
            sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
        let (typ, kind) = super::v1_type_and_kind(
            previous.family.as_deref(),
            previous.pin.as_ref().map(|p| p.version),
            primary_type.as_deref(),
            previous.kind.as_deref(),
            &previous.fields,
        );
        let bearer = kernel::v1_state::lifecycle_bearer_on(
            tx,
            move_home.as_deref().unwrap_or(&previous.home_id),
            Some(&previous.id),
        )
        .await?;
        kernel::v1_state::interpreter_on(tx, actor)
            .await?
            .validate_imported_write(
                typ.unwrap_or_default(),
                kind.unwrap_or_default(),
                Some(&bearer),
                if args.get("lifecycle").is_some() {
                    optional_text(args, "lifecycle")?
                } else {
                    previous.fields.get("lifecycle").and_then(Value::as_str)
                },
            )?;
    }
    let mut fields = Map::new();
    for (input, field) in [
        ("name", "title"),
        ("summary", "summary"),
        ("lifecycle", "lifecycle"),
    ] {
        if let Some(value) = args.get(input) {
            optional_text(args, input)?;
            if previous.family.as_deref() == Some(crate::v2_standard::DOCUMENT_FAMILY)
                && previous.pin.as_ref().is_some_and(|p| p.version < 4)
                && input != "name"
            {
                return Err(invalid(format!(
                    "Document/note definition has no {input} field"
                )));
            }
            let explicit_title_effect = input == "name"
                && origin
                    .as_ref()
                    .is_some_and(|origin| origin["effect"] == "title.set");
            if explicit_title_effect || previous.fields.get(field).unwrap_or(&Value::Null) != value
            {
                fields.insert(field.into(), value.clone());
            }
        }
    }
    let body_ops: Vec<_> = ["body", "body_set", "body_append", "body_replace"]
        .into_iter()
        .filter(|key| args.get(*key).is_some())
        .collect();
    if body_ops.len() > 1 {
        return Err(invalid("use exactly one body operation"));
    }
    let mut publish_app_source = false;
    if !body_ops.is_empty() {
        let primary_type: Option<String> =
            sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
        let (typ, kind) = super::v1_type_and_kind(
            previous.family.as_deref(),
            previous.pin.as_ref().map(|p| p.version),
            primary_type.as_deref(),
            previous.kind.as_deref(),
            &previous.fields,
        );
        if typ == Some("Document") && kind == Some("artifact") {
            if !can_publish_personal_app {
                return Err(Error::auth(
                    "app source publication requires an eligible workspace member",
                ));
            }
            if optional_text(args, "if_body_digest")?.is_none() {
                return Err(invalid("app source publication requires if_body_digest"));
            }
            kernel::app_installs::sources::require_owner_on(tx, actor, id, None).await?;
            if args.get("facets").is_some() || args.get("home_id").is_some() {
                return Err(invalid(
                    "app source publication cannot change facets or home",
                ));
            }
            if context.as_ref().is_some_and(|owner| owner.is_live()) {
                return Err(invalid("app package body writes cannot use co-edit routing; publish with update_record and if_body_digest outside an active co-edit session"));
            }
            publish_app_source = true;
        }
    }
    let next_body = if let Some(op) = body_ops.first() {
        if super::super::tools::lifecycle::whole_body_write_needs_guard(
            matches!(*op, "body" | "body_set"),
            previous.body.as_deref(),
            optional_text(args, "if_body_digest")?,
            optional_text(args, "if_unmodified_since")?,
        ) {
            return Err(invalid(
                "body_set requires if_body_digest or if_unmodified_since",
            ));
        }
        Some(match *op {
            "body" | "body_set" => optional_text(args, op)?.unwrap_or("").to_owned(),
            "body_append" => format!(
                "{}{}",
                previous.body.as_deref().unwrap_or(""),
                text(args, op)?
            ),
            "body_replace" => {
                replace_body(previous.body.as_deref().unwrap_or(""), args[op].clone())?
            }
            _ => unreachable!(),
        })
    } else {
        None
    };
    if ![
        "home_id",
        "name",
        "summary",
        "lifecycle",
        "persistence",
        "maturity",
        "body",
        "body_set",
        "body_append",
        "body_replace",
        "facets",
        "links",
    ]
    .iter()
    .any(|key| args.get(*key).is_some())
    {
        return Err(invalid("no changes supplied"));
    }
    // Fence every lane with the captured revision without emitting an empty
    // field revision for body/facet/link-only operations or no-op patches.
    if super::comments::record_is_comment(&previous) {
        let touches_part_of = args
            .get("links")
            .and_then(Value::as_array)
            .is_some_and(|links| {
                links
                    .iter()
                    .any(|link| link.get("relationship").and_then(Value::as_str) == Some("part_of"))
            });
        super::comments::check_update(
            tx,
            id,
            &previous,
            args.get("lifecycle").is_some(),
            optional_text(args, "lifecycle")?,
            args.get("summary").is_some(),
            optional_text(args, "summary")?,
            next_body.as_deref(),
            touches_part_of,
        )
        .await?;
    }
    let mut basis = match resolved_basis {
        Some(basis) => basis,
        None => {
            phase(
                Stage::SourceBasis,
                super::source_basis::resolve_on(tx, actor, args.get("sources"), "update_record"),
            )
            .await?
        }
    };
    let declared_sources = basis
        .as_ref()
        .map(|b| b["sources"].as_array().unwrap().len());
    kernel::hq::record_edit(tx, actor, id, Some(previous.revision)).await?;
    // Field revisions must see the destination's schema. Re-prove the old
    // CAS first, move the whole thread, then fence revisions at the new head.
    let edit_revision = if let Some(home) = move_home.filter(|home| home != &previous.home_id) {
        kernel::move_record_with_comments_in(db, tx, acts, actor, id, &home).await?;
        view(tx, actor, id).await?.revision
    } else {
        previous.revision
    };
    if !fields.is_empty() {
        let raw = serde_json::to_string(&fields)?;
        kernel::revise_input_with_basis_in(
            db,
            tx,
            acts,
            actor,
            id,
            kernel::FieldInput::Raw(&raw),
            Some(edit_revision),
            origin.clone(),
            basis.take(),
        )
        .await?;
    }
    phase(
        Stage::Metadata,
        metadata_patch_with_basis(db, tx, acts, actor, id, args, &mut basis),
    )
    .await?;
    let explicit_body_effect = origin
        .as_ref()
        .is_some_and(|origin| origin["effect"] == "body.set");
    let first_publication = publish_app_source
        && kernel::app_installs::sources::needs_initial_publication_on(tx, id).await?;
    if let Some(body) = next_body.filter(|body| {
        explicit_body_effect || first_publication || body != previous.body.as_deref().unwrap_or("")
    }) {
        let mut payload = json!({"body":body});
        if let Some(origin) = &origin {
            payload["origin"] = origin.clone();
        }
        let body_basis = basis.take();
        if let Some(basis) = &body_basis {
            payload["basis"] = basis.clone();
        }
        let routed = match context {
            Some(owner) => {
                // The actual Caller is retained by the operation owner; native
                // contributor minting must not reconstruct it from actor text.
                phase(
                    Stage::LiveBody,
                    owner.append_dispatched_body_with_basis_in(
                        tx,
                        id,
                        &body,
                        origin.clone(),
                        body_basis,
                        optional_text(args, "reason")?.unwrap_or("record updated"),
                        acts,
                        binding,
                    ),
                )
                .await?
            }
            None => false,
        };
        if routed && publish_app_source {
            return Err(Error::engine("app package body writes cannot use co-edit routing; publish with update_record and if_body_digest outside an active co-edit session"));
        }
        if !routed {
            phase(
                Stage::BodyEvent,
                event(db, tx, acts, actor, id, "kernel.body_set.v1", payload),
            )
            .await?;
            if publish_app_source {
                kernel::app_installs::sources::publish_on(db, tx, acts, actor, id).await?;
            }
        }
    }
    facets_with_basis(
        db,
        tx,
        acts,
        actor,
        id,
        args.get("facets"),
        "update_record",
        None,
        &mut basis,
    )
    .await?;
    // Updates never carry a comment bearer link: part_of on a comment is
    // refused by check_update above, so no bearer skips apply here.
    let targets = new_links(db, tx, acts, actor, id, args.get("links"), None).await?;
    let changed: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE seq>?)")
            .bind(before_event_seq)
            .fetch_one(&mut *tx)
            .await?;
    let effect = if changed { "updated" } else { "unchanged" };
    let mut result = phase(
        Stage::Receipt,
        receipt(tx, actor, id, effect, Some(&previous), targets),
    )
    .await?;
    if redirected_home {
        crate::mcp::tools::disclose_root_filing(&mut result);
    }
    if basis.is_some() {
        result["basis"] = json!({"status":"not_recorded", "source_count":0,
            "message":"No source basis recorded: no field, metadata, body or facet event changed."});
    } else if let Some(feedback) =
        super::super::tools::lifecycle::declared_basis_feedback(declared_sources)
    {
        result["basis"] = feedback;
    }
    Ok(result)
}

fn replace_body(body: &str, args: Value) -> Result<String> {
    let ops: Vec<crate::mcp::tools::lifecycle::BodyReplace> =
        parse("update_record.body_replace", args)?;
    crate::mcp::tools::lifecycle::apply_body_replacements("update_record", body, &ops)
}

type FacetRow = (Option<String>, Option<f64>, Option<String>, String);

pub(crate) async fn facets(
    db: &Db,
    tx: &mut SqliteConnection,
    acts: &mut ActAllocation,
    actor: &str,
    id: &str,
    values: Option<&Value>,
    tool: &str,
) -> Result<()> {
    facets_with_origin(db, tx, acts, actor, id, values, tool, None).await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn facets_with_origin(
    db: &Db,
    tx: &mut SqliteConnection,
    acts: &mut ActAllocation,
    actor: &str,
    id: &str,
    values: Option<&Value>,
    tool: &str,
    origin: Option<Value>,
) -> Result<()> {
    facets_with_basis(db, tx, acts, actor, id, values, tool, origin, &mut None).await
}

#[allow(clippy::too_many_arguments)]
async fn facets_with_basis(
    db: &Db,
    tx: &mut SqliteConnection,
    acts: &mut ActAllocation,
    actor: &str,
    id: &str,
    values: Option<&Value>,
    tool: &str,
    origin: Option<Value>,
    basis: &mut Option<Value>,
) -> Result<()> {
    let Some(values) = values.filter(|v| !v.is_null()) else {
        return Ok(());
    };
    for (key, value) in object(values)? {
        if key == "blob_ref" {
            return Err(invalid("blob_ref is engine-owned"));
        }
        if crate::schema::ENGINE_RESERVED_FACET_KEYS.contains(&key.as_str()) {
            crate::domain_transaction::assert_open_facet_key(tool, key)?;
        }
        let now = chrono::Utc::now().to_rfc3339();
        let observation = match value {
            Value::Null => kernel::FacetObservation {
                key: key.clone(),
                value: None,
                value_num: None,
                vocab_ref: None,
                as_of: now,
            },
            Value::String(_) | Value::Number(_) => {
                let parsed =
                    super::super::tools::lifecycle::parse_facet_entry(tool, key, value, false)?
                        .ok_or_else(|| invalid("facet value missing"))?;
                kernel::FacetObservation {
                    key: key.clone(),
                    value: Some(parsed.stored_value()),
                    value_num: parsed.value.as_f64(),
                    vocab_ref: parsed.vocab_ref,
                    as_of: now,
                }
            }
            Value::Object(map)
                if !(map.keys().all(|k| {
                    ["value", "value_num", "vocab_ref", "as_of"].contains(&k.as_str())
                }) && (map.contains_key("as_of")
                    || map.contains_key("value_num")
                    || map.get("value") == Some(&Value::Null))) =>
            {
                // Use v1's single object / {value,vocab_ref} grammar. An atomic
                // object is data, not an invented set of observation options.
                let parsed =
                    super::super::tools::lifecycle::parse_facet_entry(tool, key, value, false)?
                        .ok_or_else(|| invalid("facet value missing"))?;
                kernel::FacetObservation {
                    key: key.clone(),
                    value: Some(parsed.stored_value()),
                    value_num: parsed.value.as_f64(),
                    vocab_ref: parsed.vocab_ref,
                    as_of: now,
                }
            }
            Value::Object(map) => {
                if map
                    .keys()
                    .any(|k| !["value", "value_num", "vocab_ref", "as_of"].contains(&k.as_str()))
                {
                    return Err(invalid("unsupported facet observation member"));
                }
                kernel::FacetObservation {
                    key: key.clone(),
                    value: optional_text(value, "value")?.map(str::to_owned),
                    value_num: match value.get("value_num") {
                        None | Some(Value::Null) => None,
                        Some(n) => Some(
                            n.as_f64()
                                .ok_or_else(|| invalid("value_num must be a number"))?,
                        ),
                    },
                    vocab_ref: optional_text(value, "vocab_ref")?.map(str::to_owned),
                    as_of: optional_text(value, "as_of")?.unwrap_or(&now).into(),
                }
            }
            _ => return Err(invalid("facet must be text, null or an observation")),
        };
        kernel::hq::validate_facet(&observation)?;
        let explicit_as_of = value
            .as_object()
            .is_some_and(|map| map.get("as_of").is_some_and(|v| !v.is_null()));
        let current: Option<FacetRow> = sqlx::query_as(
            "SELECT value,value_num,vocab_ref,as_of FROM kernel_facets WHERE record_id=? AND key=?",
        )
        .bind(id)
        .bind(key)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((current_value, num, vocab, as_of)) = current {
            let current_time = chrono::DateTime::parse_from_rfc3339(&as_of)
                .map_err(|_| invalid("invalid stored facet as_of"))?;
            let next_time = chrono::DateTime::parse_from_rfc3339(&observation.as_of)
                .map_err(|_| invalid("invalid facet as_of"))?;
            if next_time < current_time
                || (observation.value == current_value
                    && observation.value_num == num
                    && observation.vocab_ref == vocab
                    && (!explicit_as_of || next_time == current_time))
            {
                continue;
            }
        } else if observation.value.is_none() && !explicit_as_of {
            continue;
        }
        let mut payload = serde_json::to_value(observation)?;
        if let Some(basis) = basis.take() {
            payload["basis"] = basis;
        }
        if let Some(origin) = &origin {
            payload["origin"] = origin.clone();
        }
        event(db, tx, acts, actor, id, "kernel.facet_observed.v1", payload).await?;
    }
    Ok(())
}

async fn new_links(
    db: &Db,
    tx: &mut SqliteConnection,
    acts: &mut ActAllocation,
    actor: &str,
    id: &str,
    links: Option<&Value>,
    comment_bearer: Option<&str>,
) -> Result<Vec<String>> {
    let mut targets = Vec::new();
    if let Some(links) = links.filter(|v| !v.is_null()) {
        for link in links
            .as_array()
            .ok_or_else(|| invalid("links must be an array"))?
        {
            allowed(link, &["target_id", "relationship", "note"])?;
            let target = text(link, "target_id")?;
            let relationship = text(link, "relationship")?;
            // The comment bearer link commits atomically inside creation;
            // replaying it through the ordinary lane would fence on a
            // source-Edit the chain cannot yet confer. It stays a receipt
            // target so retries re-prove bearer View.
            if Some(target) == comment_bearer && relationship == "part_of" {
                targets.push(target.to_owned());
                continue;
            }
            change_link(
                db,
                tx,
                acts,
                actor,
                id,
                target,
                relationship,
                false,
                optional_text(link, "note")?,
            )
            .await?;
            targets.push(target.to_owned());
        }
    }
    Ok(targets)
}

// Free-form directed links share the caller's transaction and act allocation.
#[allow(clippy::too_many_arguments)]
async fn directed_link(
    db: &Db,
    tx: &mut SqliteConnection,
    acts: &mut ActAllocation,
    actor: &str,
    source: &str,
    target: &str,
    relationship: &str,
    remove: bool,
    note: Option<&str>,
) -> Result<Option<kernel::GenericLinkWrite>> {
    if remove {
        kernel::generic_links::remove_generic_link_triple_in(
            db,
            tx,
            acts,
            actor,
            source,
            target,
            relationship,
        )
        .await?;
        Ok(None)
    } else {
        let write = kernel::generic_links::add_generic_link_in(
            db,
            tx,
            acts,
            actor,
            source,
            target,
            relationship,
            note.map(str::to_owned),
        )
        .await?;
        Ok(Some(write))
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn change_link(
    db: &Db,
    tx: &mut SqliteConnection,
    acts: &mut ActAllocation,
    actor: &str,
    source: &str,
    target: &str,
    relationship: &str,
    remove: bool,
    note: Option<&str>,
) -> Result<Option<kernel::GenericLinkWrite>> {
    let source_record = view(tx, actor, source).await?;
    kernel::kernel_require(tx, actor, source, Capability::Edit).await?;
    kernel::kernel_require(tx, actor, target, Capability::View).await?;
    if relationship == "part_of"
        && source_record.fields.get("v1_type").and_then(Value::as_str) == Some("Document")
        && source_record.fields.get("v1_kind").and_then(Value::as_str) == Some("attachment")
    {
        // Updating the existing bearer's note does not change its identity.
        let same_bearer: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_generic_links WHERE source_id=? AND target_id=? AND relationship='part_of' AND active=1)")
            .bind(source).bind(target).fetch_one(&mut *tx).await?;
        if remove || !same_bearer {
            return Err(invalid("manage_links: Document kind:attachment requires exactly one outgoing part_of link to its bearer; use attach_text to create a new attachment"));
        }
    }
    if !relation::reserves(relationship) {
        return directed_link(
            db,
            tx,
            acts,
            actor,
            source,
            target,
            relationship,
            remove,
            note,
        )
        .await;
    }
    kernel::kernel_require(tx, actor, source, Capability::Edit).await?;
    kernel::kernel_require(tx, actor, target, Capability::View).await?;
    let mut commands = Vec::new();
    if remove {
        for assertion_id in
            kernel::relates_to_port::removable_assertions_on(tx, actor, source, target).await?
        {
            commands.push(relation::Command::Retract { assertion_id });
        }
        if commands.is_empty() {
            return Err(Error::conflict(
                "no own or imported assertion to retract; the link may be absent",
            ));
        }
    } else {
        commands.push(relation::Command::Assert {
            sources: vec![relation::Source {
                source_id: uuid::Uuid::new_v4().to_string(),
                from: source.into(),
                to: target.into(),
                claimed_author: None,
                claimed_timestamp: None,
                note: note.map(str::to_owned),
            }],
        });
    }
    for command in commands {
        let request = kernel::relates_to_port::prepare_provider_on(
            tx,
            actor,
            source,
            target,
            &uuid::Uuid::new_v4().to_string(),
            command,
        )
        .await?;
        kernel::relates_to_port::commit_provider_in(db, tx, acts, actor, &request).await?;
    }
    Ok(None)
}

async fn mutate_link(
    db: &Db,
    tx: &mut SqliteConnection,
    acts: &mut ActAllocation,
    actor: &str,
    args: &Value,
) -> Result<Value> {
    allowed(
        args,
        &[
            "action",
            "source_id",
            "target_id",
            "relationship",
            "note",
            "idempotency_key",
        ],
    )?;
    let remove = match text(args, "action")? {
        "add" => false,
        "remove" => true,
        _ => return Err(invalid("unsupported manage_links action")),
    };
    let source = text(args, "source_id")?;
    let target = text(args, "target_id")?;
    let previous = view(tx, actor, source).await?;
    if text(args, "relationship")? == "part_of" && super::comments::record_is_comment(&previous) {
        return Err(Error::engine(
            "update_record: a governed comment's part_of bearer is immutable; create a new comment instead",
        ));
    }
    let link = change_link(
        db,
        tx,
        acts,
        actor,
        source,
        target,
        text(args, "relationship")?,
        remove,
        optional_text(args, "note")?,
    )
    .await?;
    let relation_active = if remove && relation::reserves(text(args, "relationship")?) {
        let mut active = false;
        for row in kernel::relates_to_port::relations_in(tx, actor, source).await? {
            let state: relation::State = serde_json::from_value(row["state"].clone())?;
            if (state.left == target || state.right == target)
                && state.assertions.iter().any(|a| !a.retracted)
            {
                active = true;
            }
        }
        Some(active)
    } else {
        None
    };
    let effect = if let Some(write) = &link {
        match write.outcome {
            kernel::GenericLinkOutcome::Created => "link_added",
            kernel::GenericLinkOutcome::Updated => "link_note_updated",
            kernel::GenericLinkOutcome::Unchanged => "unchanged",
        }
    } else if !relation::reserves(text(args, "relationship")?)
        && view(tx, actor, source).await?.revision == previous.revision
    {
        "unchanged"
    } else if relation_active == Some(true) {
        "link_assertions_retracted"
    } else if remove {
        "link_removed"
    } else {
        "link_added"
    };
    let mut result = receipt(
        tx,
        actor,
        source,
        effect,
        Some(&previous),
        vec![target.into()],
    )
    .await?;
    if let Some(write) = link {
        let link = write.link;
        result["link"] = json!({"id":link.link_id,"source_id":link.source_id,"target_id":link.target_id,"relationship":link.relationship,"note":link.note,"created_at":link.created_at});
    }
    result["action"] = args["action"].clone();
    result["source_id"] = json!(source);
    result["target_id"] = json!(target);
    result["relationship"] = args["relationship"].clone();
    result["status"] = json!(if relation_active == Some(true) {
        "assertions_retracted"
    } else if remove {
        "removed"
    } else {
        "added"
    });
    if let Some(active) = relation_active {
        result["relationship_active_after_operation"] = json!(active);
    }
    Ok(result)
}

type LinkKey = (u8, String, String, String, String, String);

async fn list_links(db: &Db, actor: &str, args: Value) -> Result<Value> {
    allowed(&args, &["action", "record_id", "limit", "cursor"])?;
    let id = text(&args, "record_id")?;
    let limit = args
        .get("limit")
        .filter(|v| !v.is_null())
        .map(|n| n.as_u64().ok_or_else(|| invalid("limit must be 1..200")))
        .transpose()?
        .unwrap_or(50) as usize;
    if !(1..=200).contains(&limit) {
        return Err(invalid("limit must be 1..200"));
    }
    let cursor = optional_text(&args, "cursor")?;
    let after = if let Some(cursor) = cursor {
        let value = db
            .get_inbox_snapshot(cursor)
            .map_err(|_| invalid("cursor_reset_required: invalid link cursor"))?;
        if value["schema"] != "kernel-v2.links.1"
            || value["actor"] != actor
            || value["record"] != id
            || value["limit"] != limit
        {
            return Err(invalid(
                "cursor_reset_required: link cursor does not match caller, record, or limit",
            ));
        }
        Some(
            serde_json::from_value::<LinkKey>(value["key"].clone())
                .map_err(|_| invalid("cursor_reset_required: malformed link key"))?,
        )
    } else {
        None
    };
    let rows = kernel::generic_links::visible_link_rows_as(db, actor, id).await?;
    let mut candidates = Vec::new();
    for rank in [0, 1] {
        for row in &rows {
            if row[if rank == 0 { "source_id" } else { "target_id" }] == id {
                let text = |field: &str| row[field].as_str().unwrap_or("").to_owned();
                let key: LinkKey = (
                    rank,
                    text("relationship"),
                    text("created_at"),
                    text("id"),
                    text("source_id"),
                    text("target_id"),
                );
                candidates.push((key, row.clone(), rank));
            }
        }
    }
    if let Some(after) = after {
        candidates.retain(|(key, _, _)| *key > after);
    }
    let has_more = candidates.len() > limit;
    candidates.truncate(limit);
    let next_cursor = if has_more {
        Some(db.put_inbox_snapshot(json!({"schema":"kernel-v2.links.1","actor":actor,"record":id,"limit":limit,"key":candidates.last().unwrap().0}))?)
    } else {
        None
    };
    let mut links_out = Vec::new();
    let mut links_in = Vec::new();
    for (_, row, rank) in candidates {
        if rank == 0 {
            links_out.push(row);
        } else {
            links_in.push(row);
        }
    }
    // Preserve the original probe alias: outbound only. V1 callers use the
    // two directional arrays and their combined returned count.
    let links = links_out.clone();
    let returned = links_out.len() + links_in.len();
    let next_call = next_cursor
        .as_ref()
        .map(|cursor| json!({"action":"list","record_id":id,"limit":limit,"cursor":cursor}));
    Ok(
        json!({"action":"list","format":"native.manage-links-list.v1","record_id":id,"viewer_relative":true,"query_basis":"live_at_each_page_read","scope":"opposite_endpoint_viewable_at_read_time","limit":limit,"cursor":cursor,"links_out":links_out,"links_in":links_in,"returned":returned,"links":links,"has_more":has_more,"next_cursor":next_cursor,"next_call":next_call,"kernel_v2":{"atomic":true}}),
    )
}

#[cfg(test)]
mod tests;

/// Probe responses retain kernel event identities instead of inventing v1
/// relationship-log coordinates. Use the ordinary tool's text surface too.
pub(crate) fn render_links(value: &Value) -> String {
    if value["action"] == "list" {
        let links: Vec<_> = ["links_out", "links_in"]
            .into_iter()
            .flat_map(|key| value[key].as_array().expect("adapter-authored link list"))
            .collect();
        let mut out = format!(
            "{} visible links for {}\n",
            links.len(),
            value["record_id"].as_str().unwrap_or("")
        );
        for link in links {
            out.push_str(&format!(
                "  {} → {} ({})\n",
                link["source_id"].as_str().unwrap_or(""),
                link["target_id"].as_str().unwrap_or(""),
                link["relationship"].as_str().unwrap_or("")
            ));
        }
        out
    } else if value["changed"] == false {
        format!(
            "Link unchanged: {} → {} ({})\n",
            value["source_id"].as_str().unwrap_or(""),
            value["target_id"].as_str().unwrap_or(""),
            value["relationship"].as_str().unwrap_or("")
        )
    } else if value["effect"] == "link_assertions_retracted" {
        format!("Own/imported assertions retracted; other assertions keep this relationship active.\nKernel event: {}\n",value["write_receipt"]["event"]["seq"])
    } else if value["effect"] == "link_note_updated" {
        format!(
            "Existing link note updated: {} → {} ({})\nKernel event: {}\n",
            value["source_id"].as_str().unwrap_or(""),
            value["target_id"].as_str().unwrap_or(""),
            value["relationship"].as_str().unwrap_or(""),
            value["write_receipt"]["event"]["seq"]
        )
    } else {
        format!(
            "Link {} committed: {} → {} ({})\nKernel event: {}\n",
            value["action"].as_str().unwrap_or(""),
            value["source_id"].as_str().unwrap_or(""),
            value["target_id"].as_str().unwrap_or(""),
            value["relationship"].as_str().unwrap_or(""),
            value["write_receipt"]["event"]["seq"]
        )
    }
}

pub(super) async fn attach_text(
    db: &Db,
    tx: &mut Transaction<'_, Sqlite>,
    acts: &mut ActAllocation,
    actor: &str,
    args: &Value,
) -> Result<Value> {
    let mint = mint_evidence(actor, args, "attachment_id")?;
    allowed(
        args,
        &[
            "attachment_id",
            "id_nonce",
            "record_id",
            "text",
            "filename",
            "mime",
            "name",
            "lifecycle",
            "facets",
            "idempotency_key",
        ],
    )?;
    if mint.is_some() {
        refuse_minted_occupancy(tx, text(args, "attachment_id")?).await?;
    }
    let bearer = text(args, "record_id")?;
    kernel::kernel_require(tx, actor, bearer, Capability::Edit).await?;
    let parent = view(tx, actor, bearer).await?;
    let home = if parent.fields.get("v1_type").and_then(Value::as_str) == Some("Collection")
        && parent.fields.get("v1_kind").and_then(Value::as_str) == Some("folder")
    {
        if parent.archived {
            return Err(invalid("attachment folder is archived"));
        }
        crate::v1_import::resolve_home_on(tx, actor, bearer).await?
    } else {
        parent.home_id
    };
    let bytes = text(args, "text")?.as_bytes();
    if bytes.len() > crate::mcp::fetch::MAX_FETCH_BYTES as usize {
        return Err(invalid("text exceeds 20971520 byte limit"));
    }
    let mime = optional_text(args, "mime")?.unwrap_or("text/plain; charset=utf-8");
    let filename = optional_text(args, "filename")?;
    let name = optional_text(args, "name")?
        .or(filename)
        .unwrap_or("attachment");
    let mut meta = crate::blob::new_blob_meta(bytes, Some(mime), filename);
    meta.id = meta.sha256.clone();
    kernel::blobs::put(tx, bytes, &meta).await?;
    validate_lifecycle(args)?;
    let fields = v1_compat::compat_fields(
        "Document",
        "attachment",
        Some(name),
        None,
        optional_text(args, "lifecycle")?,
    );
    let raw = serde_json::to_string(&fields)?;
    let id = kernel::create_attachment_input_in(
        db,
        tx,
        acts,
        actor,
        bearer,
        kernel::FieldInput::Raw(&raw),
        &home,
        optional_text(args, "attachment_id")?,
        mint,
    )
    .await?;
    facets(db, tx, acts, actor, &id, args.get("facets"), "attach_text").await?;
    kernel::blobs::bind(db, tx, acts, actor, &id, &meta).await?;
    event(
        db,
        tx,
        acts,
        actor,
        &id,
        "kernel.facet_observed.v1",
        json!(kernel::FacetObservation {
            key: "blob_ref".into(),
            value: Some(meta.id.clone()),
            value_num: None,
            vocab_ref: None,
            as_of: crate::store::now_iso()
        }),
    )
    .await?;
    kernel::generic_links::add_generic_link_in(db, tx, acts, actor, &id, bearer, "part_of", None)
        .await?;
    Ok(json!({"attachment_id":id,"record_id":bearer,"name":name,"blob":meta,"act":acts.get()}))
}

#[cfg(test)]
pub(crate) async fn with_minted_ids_for_settlement_test<F: std::future::Future>(
    work: F,
) -> F::Output {
    MINTED_IDS_TEST.scope(true, work).await
}

#[cfg(all(test, feature = "v2-kernel-probe", feature = "mcp-executor-prototype"))]
mod original_settlement_writer_tests;
