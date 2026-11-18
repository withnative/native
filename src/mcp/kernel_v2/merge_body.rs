//! KernelV2 `merge_body` (design `docs/design/body-merge-home.md`, sections 2
//! and 7). The engine-independent half (descriptor, evaluator, refusal and
//! receipt shapes) is `mcp::tools::merge_body`.
//!
//! # Order of checks
//!
//! Everything runs in one [`KernelTransaction`] on the writer:
//!
//! 1. shape and size of the arguments (no record state is read);
//! 2. app admission: an app-attributed caller is re-admitted on this
//!    transaction (current consent and source View), exactly as `update_record`
//!    does; an ordinary caller passes through;
//! 3. authorise as the principal: Edit on the record, so the intent carries no
//!    authority of its own (a folder-scoped app is narrowed here, and a record
//!    outside its grant reads as `record_missing`);
//! 4. keyed replay lookup in `kernel_mcp_write_receipts`, which returns the
//!    stored receipt verbatim, whatever the record or the flag now say;
//! 5. the account flag, `feature_not_enabled`, before any work;
//! 6. a live session open on the record, `home_busy`;
//! 7. record eligibility, then base validation;
//! 8. evaluate; for an app-attributed caller, append the app action's
//!    `ACTION_STARTED` (only now, after every refusal and before any content
//!    event), then the body event if the merge changes the text, then
//!    `ACTION_RECORDED`, then store the receipt with its `app_attribution`
//!    block. Unchanged and clash-only outcomes record the action with no
//!    outputs, as `update_record` always records one.
//!
//! A refusal rolls the transaction back, so it is never stored under the key
//! and a retry evaluates afresh. Only the three success-shaped outcomes
//! (`merged` with a write, `merged` unchanged, `merged_with_clashes`) store a
//! receipt, in the same transaction as the event they describe.
//!
//! # Live sessions
//!
//! The write mode is [`KernelWriteMode::ReplayOnly`]: acquiring the record's
//! ownership never flushes a dirty session or retires its grace, so a replay
//! or a refusal leaves the session exactly as it was. If a session is open
//! after authorisation, replay and the flag, the call refuses `home_busy`.
//! Routing a merge into a v2 session is deliberately not implemented here.
use super::{principal, principal_on, writes};
use crate::{
    act::ActAllocation,
    authorization::Capability,
    coedit::live::kernel_writes::{
        owned_result, KernelBodyWrite, KernelTransaction, KernelWriteMode,
    },
    db::Db,
    kernel,
    mcp::registry::{Caller, EngineHandle, EngineKind, ToolRegistry},
    mcp::tools::{
        lifecycle::body_digest,
        merge_body::{
            evaluate, parse_base_version, refused, render, Evaluation, Refusal, Rendered,
            BAD_INTENT, BASE_UNVERIFIED, FEATURE_NOT_ENABLED, HOME_BUSY, MAX_TEXT_BYTES,
            NOT_PERMITTED, RECORD_MISSING, RECORD_NOT_TEXT, TOOL,
        },
    },
    Error, Result,
};
use serde::Deserialize;
use serde_json::{json, Value};

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_engine_handler(
        TOOL,
        EngineKind::KernelV2,
        |engine, caller, arguments| async move {
            let EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            let actor = principal(&db, &caller).await?;
            execute(&db, &actor, &caller, arguments).await
        },
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    record_id: String,
    base_version: String,
    base_text: String,
    my_text: String,
    reason: String,
    idempotency_key: String,
}

fn invalid(message: impl Into<String>) -> Error {
    Error::engine(format!("{TOOL}: {}", message.into()))
}

fn parse_args(arguments: Value) -> Result<(Args, String)> {
    let args: Args = serde_json::from_value(arguments).map_err(|e| invalid(e.to_string()))?;
    if args.reason.trim().is_empty() {
        return Err(invalid("reason must not be blank"));
    }
    if args.record_id.trim().is_empty() {
        return Err(invalid("record_id must not be blank"));
    }
    let key = args.idempotency_key.trim().to_owned();
    if key.is_empty() || key.chars().count() > 200 {
        return Err(invalid("idempotency_key must be 1..200 characters"));
    }
    Ok((args, key))
}

/// How one pass through the transaction ended.
enum Step {
    /// Receipt stored (and any event appended): commit.
    Commit(Value),
    /// Nothing to keep: a refusal or a replay. Roll back.
    Rollback(Value),
}

const ROLLBACK_MARK: &str = "merge_body: rolled back without an error";

async fn execute(db: &Db, actor: &str, caller: &Caller, arguments: Value) -> Result<Value> {
    let (args, key) = parse_args(arguments.clone())?;
    // Size is a property of the arguments alone, so this reads no record state.
    if args.base_text.len() > MAX_TEXT_BYTES || args.my_text.len() > MAX_TEXT_BYTES {
        return Ok(refused(&args.record_id, &key, &BAD_INTENT));
    }
    let request_json = writes::dispatched_fingerprint(TOOL, arguments)?;
    let (db, actor, caller) = (db.clone(), actor.to_owned(), caller.clone());
    #[cfg(test)]
    let fixture_owner =
        crate::coedit::live::kernel_writes::capture_writer_fixture_owner_for_test(&db);
    owned_result(db.clone(), async move {
        // Replay-only ownership: never flushes, never retires grace.
        #[cfg(test)]
        let ownership = KernelBodyWrite::acquire_fixture_owned_update_for_test(
            &db,
            &caller,
            Some(&args.record_id),
            KernelWriteMode::ReplayOnly,
            fixture_owner,
        )
        .await?;
        #[cfg(not(test))]
        let ownership = KernelBodyWrite::acquire(
            &db,
            &caller,
            Some(&args.record_id),
            KernelWriteMode::ReplayOnly,
        )
        .await?;
        let mut transaction =
            KernelTransaction::begin(&db, ownership, KernelBodyWrite::quarantine).await?;
        let step = async {
            {
                let (tx, _) = transaction.parts();
                let current = principal_on(tx, &caller).await?;
                if current != actor {
                    return Err(Error::auth("kernel writer caller binding changed"));
                }
            }
            run(
                &db,
                &mut transaction,
                &caller,
                &actor,
                &args,
                &key,
                &request_json,
            )
            .await
        }
        .await;
        match step {
            Ok(Step::Commit(receipt)) => {
                {
                    let (tx, ownership) = transaction.parts();
                    if let Err(error) = ownership.validate_in(tx).await {
                        return Err(transaction.rollback(error).await);
                    }
                }
                let mut ownership = transaction.commit().await?;
                ownership.install_committed()?;
                Ok(receipt)
            }
            Ok(Step::Rollback(value)) => {
                let error = transaction.rollback(Error::engine(ROLLBACK_MARK)).await;
                if error.to_string() == Error::engine(ROLLBACK_MARK).to_string() {
                    Ok(value)
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(transaction.rollback(error).await),
        }
    })
    .await
}

fn refuse(args: &Args, key: &str, refusal: &Refusal) -> Result<Step> {
    Ok(Step::Rollback(refused(&args.record_id, key, refusal)))
}

async fn run(
    db: &Db,
    transaction: &mut KernelTransaction<KernelBodyWrite>,
    caller: &Caller,
    actor: &str,
    args: &Args,
    key: &str,
    request_json: &str,
) -> Result<Step> {
    let id = args.record_id.as_str();
    let live = transaction.parts().1.is_live();
    let tx = transaction.parts().0;

    kernel::mcp_write_receipts::fences::refuse_key_on(tx, actor, TOOL, key).await?;
    // App-attributed callers: current consent and source View are checked on
    // this connection before anything else, exactly as `update_record` does.
    // The action itself is started (step 8) only once the call is going to
    // evaluate and store an outcome.
    kernel::app_installs::admit_dispatched_on(tx, actor).await?;

    // 1. Authorise as the principal. A record the caller cannot see reads as
    // missing; one they can see but not edit is not_permitted.
    let capability = match kernel::kernel_effective_capability_on(tx, actor, id).await {
        Ok(capability) => capability,
        // An unknown id reads as missing, exactly as a hidden one does.
        Err(error) if error.to_string().contains(kernel::HIDDEN_OR_MISSING) => {
            return refuse(args, key, &RECORD_MISSING);
        }
        Err(error) => return Err(error),
    };
    if !capability.allows(Capability::View) {
        return refuse(args, key, &RECORD_MISSING);
    }
    if !capability.allows(Capability::Edit) {
        return refuse(args, key, &NOT_PERMITTED);
    }

    // 2. Keyed replay. Authorisation came first, so a stored receipt is not an
    // existence oracle, and it is returned whatever the flag or record now say.
    sqlx::query(writes::RECEIPTS).execute(&mut *tx).await?;
    let earlier: Option<(String, String)> = sqlx::query_as(
        "SELECT request_json,receipt_json FROM kernel_mcp_write_receipts WHERE principal_id=? AND operation=? AND operation_key=?",
    )
    .bind(actor)
    .bind(TOOL)
    .bind(key)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((old_request, receipt)) = earlier {
        if writes::stored_fingerprint(TOOL, serde_json::from_str(&old_request)?)? != request_json {
            return Err(Error::conflict(
                "idempotency_key reused for different request",
            ));
        }
        return Ok(Step::Rollback(serde_json::from_str(&receipt)?));
    }

    // 3. The account flag, before any work.
    if !crate::body_merge_flag::account_enabled(caller.credential()) {
        return refuse(args, key, &FEATURE_NOT_ENABLED);
    }

    // 4. A live session on the record. Routing into one is not implemented.
    if live {
        return refuse(args, key, &HOME_BUSY);
    }

    // 5. Eligibility: an ordinary record with a text body. Messages are
    // sealed, comments and artifacts have their own write lanes.
    let Some(view) = kernel::read_record_on(tx, actor, id).await? else {
        return refuse(args, key, &RECORD_MISSING);
    };
    if !is_plain_text_record(tx, id, &view).await? {
        return refuse(args, key, &RECORD_NOT_TEXT);
    }

    // 6. Base validation: the version must name a content event of THIS record
    // and the body folded at it must be `base_text`.
    let Some(base_seq) = parse_base_version(&args.base_version) else {
        return refuse(args, key, &BASE_UNVERIFIED);
    };
    let named: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND seq=?)",
    )
    .bind(id)
    .bind(base_seq)
    .fetch_one(&mut *tx)
    .await?;
    if !named {
        return refuse(args, key, &BASE_UNVERIFIED);
    }
    let base_body = kernel::historical::body_at_on(tx, actor, id, base_seq)
        .await?
        .unwrap_or_default();
    if body_digest(Some(&base_body)) != body_digest(Some(&args.base_text)) {
        return refuse(args, key, &BASE_UNVERIFIED);
    }

    // 7. Evaluate against what the world shows now: the body folded at the
    // observed horizon, the same function the next base check will use.
    let observed = view.revision;
    let theirs = kernel::historical::body_at_on(tx, actor, id, observed)
        .await?
        .unwrap_or_default();
    let (base, mine, theirs_text) = (args.base_text.clone(), args.my_text.clone(), theirs);
    let (evaluation, theirs_text): (Evaluation, String) = tokio::task::spawn_blocking(move || {
        let evaluation = evaluate(&base, &mine, &theirs_text);
        (evaluation, theirs_text)
    })
    .await
    .map_err(|error| invalid(format!("merge failed: {error}")))?;
    // Every outcome is bounded: a body above the ceiling could not be the next
    // call's base_text.
    if evaluation.merged.len() > MAX_TEXT_BYTES {
        return refuse(args, key, &BAD_INTENT);
    }
    let merged_offline = theirs_text != args.base_text;

    // 8. Write. Only a merge that changes the text appends an event, the same
    // `kernel.body_set.v1` an `update_record` body write appends.
    //
    // An app-attributed call appends ACTION_STARTED before the content event
    // and ACTION_RECORDED after it, and the receipt carries `app_attribution`.
    // This happens for every stored outcome, including unchanged and
    // clash-only merges that write no content event (the recorded action then
    // lists no outputs): like `update_record`, an app call that stores a
    // receipt always leaves an audit trail. Refusals roll back, so they leave
    // none.
    let mut acts = ActAllocation::new();
    let request_digest = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(request_json.as_bytes()))
    };
    let pending = kernel::app_installs::start_app_action_in(
        db,
        tx,
        actor,
        TOOL,
        request_digest,
        Some(args.reason.clone()),
        &mut acts,
    )
    .await?;
    let mut act = None;
    let mut write_receipt: Option<Value> = None;
    let version = if evaluation.changed {
        kernel::hq::record_edit(tx, actor, id, Some(observed)).await?;
        writes::event(
            db,
            tx,
            &mut acts,
            actor,
            id,
            "kernel.body_set.v1",
            json!({"body": evaluation.merged}),
        )
        .await?;
        // The v2 write-receipt convention: the appended event, present only
        // when this call appended one.
        let (seq, event_id, event_type, record_id, created_at, event_act): (
            i64,
            String,
            String,
            String,
            String,
            Option<i64>,
        ) = sqlx::query_as(
            "SELECT seq,id,type,record_id,created_at,act FROM content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        act = event_act;
        write_receipt = Some(
            json!({"kind":"kernel_content_event","event":{"seq":seq,"event_id":event_id,"event_type":event_type,"record_id":record_id,"created_at":created_at}}),
        );
        sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(MAX(seq),0) FROM content_events WHERE record_id=?",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?
    } else {
        observed
    };

    // 9. The receipt: one (version, body) pair from one observed state, stored
    // in the same transaction and replayed verbatim.
    let mut receipt = render(Rendered {
        record_id: id,
        key,
        base_version: &args.base_version,
        merged_offline,
        evaluation: &evaluation,
        version,
        body: &evaluation.merged,
        act,
        write_receipt,
    });
    if let Some(attribution) =
        kernel::app_installs::finish_app_action_in(db, tx, actor, pending, &mut acts).await?
    {
        receipt["app_attribution"] = attribution;
    }
    kernel::mcp_write_receipts::record_on(
        db,
        tx,
        &mut acts,
        kernel::mcp_write_receipts::Outcome {
            principal: actor,
            operation: TOOL,
            key,
            request: request_json,
            receipt: &serde_json::to_string(&receipt)?,
        },
    )
    .await?;
    Ok(Step::Commit(receipt))
}

/// An ordinary record whose body `update_record` would write as a plain body.
async fn is_plain_text_record(
    tx: &mut sqlx::SqliteConnection,
    id: &str,
    view: &kernel::KernelRecordView,
) -> Result<bool> {
    if kernel::messaging::is_message(tx, id).await? || super::comments::record_is_comment(view) {
        return Ok(false);
    }
    let primary_type: Option<String> =
        sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    let (typ, kind) = super::v1_type_and_kind(
        view.family.as_deref(),
        view.pin.as_ref().map(|p| p.version),
        primary_type.as_deref(),
        view.kind.as_deref(),
        &view.fields,
    );
    Ok(!(typ == Some("Document") && kind == Some("artifact")))
}
