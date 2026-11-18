//! One management writer for MCP and future UI executor callers. The kernel
//! owns publication authority; a hosted route index is a separate projection.
use super::*;
use kernel::publications::{self, PublicationAction, PublicationRequest};
use sha2::{Digest, Sha256};

#[cfg(test)]
tokio::task_local! { static TEST_ENABLED: bool; }

pub(crate) fn require_enabled() -> Result<()> {
    #[cfg(test)]
    let enabled = TEST_ENABLED.try_with(|v| *v).unwrap_or(false);
    #[cfg(not(test))]
    let enabled = {
        static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ENABLED
            .get_or_init(|| std::env::var("NATIVE_PUBLICATION_MANAGEMENT").as_deref() == Ok("1"))
    };
    if !enabled {
        return Err(Error::engine(
            "publication_disabled: management admission is disabled",
        ));
    }
    Ok(())
}
#[cfg(test)]
pub(crate) async fn testing<T>(enabled: bool, work: impl std::future::Future<Output = T>) -> T {
    TEST_ENABLED.scope(enabled, work).await
}
fn admit_caller(caller: &Caller) -> Result<()> {
    // App attribution needs installation admission and an atomic attribution
    // receipt in the kernel transaction. This increment does not provide it.
    if caller.host_asserted_app().is_some() || kernel::app_installs::dispatched_identity().is_some()
    {
        return Err(Error::engine(
            "publication_profile_unsupported: app-attributed publication management is unavailable",
        ));
    }
    Ok(())
}
fn canonical(db: &Db) -> Result<()> {
    if db.open_mode() != crate::db::DatabaseOpenMode::ReadWrite {
        return Err(Error::engine(
            "publication_profile_unsupported: canonical v2 writer required",
        ));
    }
    Ok(())
}
pub(crate) fn request(args: &Value) -> Result<PublicationRequest> {
    let action = text(args, "action")?;
    allowed(
        args,
        if action == "publish" {
            &[
                "action",
                "id",
                "expected_revision",
                "expected_publication_version",
                "operation_key",
                "reason",
            ]
        } else if action == "unpublish" {
            &[
                "action",
                "id",
                "public_id",
                "expected_revision",
                "expected_publication_version",
                "operation_key",
                "reason",
            ]
        } else {
            return Err(invalid("unsupported publication mutation"));
        },
    )?;
    let reason = text(args, "reason")?;
    if reason.trim().is_empty() || reason.len() > 512 {
        return Err(invalid(
            "reason must be nonblank and at most 512 UTF-8 bytes",
        ));
    }
    let key = text(args, "operation_key")?;
    if key.trim().is_empty() || key.len() > 256 {
        return Err(invalid("invalid publication operation key"));
    }
    let expected_revision = args["expected_revision"]
        .as_i64()
        .filter(|n| *n >= 0)
        .ok_or_else(|| invalid("expected_revision required"))?;
    let expected_publication_version = match args.get("expected_publication_version") {
        Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_i64()
                .filter(|n| *n > 0)
                .ok_or_else(|| invalid("invalid expected_publication_version"))?,
        ),
        None => {
            return Err(invalid(
                "expected_publication_version required, including explicit null",
            ))
        }
    };
    Ok(PublicationRequest {
        record_id: text(args, "id")?.into(),
        action: if action == "publish" {
            PublicationAction::Publish
        } else {
            PublicationAction::Revoke {
                public_id: text(args, "public_id")?.into(),
            }
        },
        expected_revision,
        expected_publication_version,
        operation_key: key.into(),
    })
}

pub(crate) async fn preview(
    db: &Db,
    caller: &Caller,
    args: &Value,
) -> Result<(Value, publications::PublicationBinding)> {
    require_enabled()?;
    admit_caller(caller)?;
    canonical(db)?;
    let actor = super::super::principal(db, caller).await?;
    let request = request(args)?;
    let (revision, state, representation, binding) = match request.action {
        PublicationAction::Publish => {
            let p = publications::prepare_as(db, &actor, &request.record_id).await?;
            (
                p.record_revision,
                p.publication,
                json!({"title_sha256":hex::encode(Sha256::digest(p.title.as_bytes())), "title_bytes":p.title.len(),
                    "body_sha256":p.body_sha256,"body_bytes":p.body.len(),"format":"markdown"}),
                p.binding,
            )
        }
        PublicationAction::Revoke { .. } => {
            let (revision, state, binding) =
                publications::inspect_bound_revision_as(db, &actor, &request.record_id).await?;
            (revision, state, Value::Null, binding)
        }
    };
    if revision != request.expected_revision
        || state.as_ref().map(|s| s.version) != request.expected_publication_version
    {
        return Err(Error::conflict(
            "publication_cas_conflict: record or publication revision changed",
        ));
    }
    match &request.action {
        PublicationAction::Publish if state.as_ref().is_some_and(|s| s.active) => {
            return Err(Error::conflict("publication_already_active"))
        }
        PublicationAction::Revoke { public_id }
            if !state
                .as_ref()
                .is_some_and(|s| s.active && s.public_id == *public_id) =>
        {
            return Err(Error::conflict(
                "publication_inactive: no matching active publication",
            ))
        }
        _ => {}
    }
    Ok((
        json!({"request":request,"record_revision":revision,"publication":state,"representation":representation,
        "consent":{"mode":"live_saved_content","fields":["title","body"],"images":"alt_text_only",
        "future_saved_edits_public":true,"dirty_editor_content_public":false,
        "persists_rehome_and_private_policy_tightening":true,"ends_on":["explicit_revocation","archive","delete","import_removal"]},
        "routing":{"status":"not_configured","public_url":null}}),
        binding,
    ))
}

pub(crate) async fn authorize_retry(db: &Db, caller: &Caller, args: &Value) -> Result<()> {
    require_enabled()?;
    admit_caller(caller)?;
    canonical(db)?;
    let actor = super::super::principal(db, caller).await?;
    let request = request(args)?;
    publications::inspect_as(db, &actor, &request.record_id).await?;
    Ok(())
}

pub(super) async fn execute(db: &Db, caller: &Caller, args: Value) -> Result<Value> {
    require_enabled()?;
    admit_caller(caller)?;
    let actor = super::super::principal(db, caller).await?;
    if args["action"] == "preview" {
        allowed(&args, &["action", "id"])?;
        canonical(db)?;
        let id = text(&args, "id")?;
        let preview = publications::prepare_as(db, &actor, id).await?;
        return Ok(json!({"id":id,"preview":preview,
            "routing":{"status":"not_configured","public_url":null}}));
    }
    if args["action"] == "inspect" {
        allowed(&args, &["action", "id"])?;
        let id = text(&args, "id")?;
        let (revision, state) = publications::inspect_revision_as(db, &actor, id).await?;
        let authority = if db.open_mode() == crate::db::DatabaseOpenMode::ReadWrite {
            "canonical_kernel"
        } else {
            "recorded_copy_not_current_authority"
        };
        return Ok(
            json!({"id":id,"record_revision":revision,"publication":state,"authority":authority,
            "routing":{"status":"not_configured","public_url":null}}),
        );
    }
    canonical(db)?;
    let action = text(&args, "action")?;
    let operation = format!("manage_publication.{action}");
    if !caller
        .write_plan_execution()
        .is_some_and(|p| p.executor == "records_write" && p.operation == operation)
    {
        return Err(Error::engine(
            "publication_executor_required: call the records_write publication operation with its arguments",
        ));
    }
    // Rights and both revisions are checked again by change_as while holding
    // the kernel writer. Do not preview here: withdrawal must work even when
    // current content is oversized or no longer supported by the reader.
    let request = request(&args)?;
    let id = request.record_id.clone();
    let receipt = publications::change_as(db, &actor, request).await?;
    #[cfg(feature = "mcp-executor-prototype")]
    crate::mcp::executor_prototype::record_publication_completion(&receipt);
    Ok(
        json!({"id":id,"operation":operation,"kernel_receipt":receipt,
        "routing":{"status":"not_configured","public_url":null},
        "write_receipt":{"kind":"kernel_content_event","event_id":receipt.event_id}}),
    )
}
