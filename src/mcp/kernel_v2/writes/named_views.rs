//! Gated event producers. Publication authority is deliberately one function.
use super::*;
use crate::named_views::{
    self as views, closure, contract, gate, Action, Pin, Revision, Transition, REVISION, TRANSITION,
};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

/// Drafts require bearer Edit. Shared publication requires workspace owner
/// footing, never home-collection Manage. The executor holds the existing
/// hosted catalog guard across effectful dispatch, so this role proof stays
/// current through this transaction. Closure View is checked by the resolver.
async fn authority_on(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    id: &str,
    publication: bool,
    caller: &crate::mcp::Caller,
) -> Result<()> {
    if publication && (caller.hosting_database().is_none() || !caller.counter_footing().is_owner())
    {
        return Err(Error::auth("view_publication_requires_workspace_owner"));
    }
    kernel::kernel_require(tx, actor, id, Capability::Edit).await
}
fn publication(args: &Value) -> bool {
    matches!(
        args["action"].as_str(),
        Some("activate_view" | "unpublish_view")
    )
}
fn exact(args: &Value) -> Result<Pin> {
    Ok(serde_json::from_value(args["pin"].clone())?)
}
fn record_id(args: &Value) -> Result<&str> {
    text(args, "id")
}
fn expected(args: &Value) -> Result<Option<String>> {
    match args.get("expected_binding_event_id") {
        Some(Value::Null) => Ok(None),
        Some(Value::String(id)) => Ok(Some(id.clone())),
        _ => Err(Error::engine(
            "expected_binding_event_id must be an exact event ID or explicit null",
        )),
    }
}
fn check_cas(state: &views::ReplayChecker, args: &Value, id: &str) -> Result<()> {
    if state
        .bindings
        .get(&format!("native.named-view:{id}"))
        .map(|b| b.event_id.clone())
        != expected(args)?
    {
        return Err(Error::conflict(
            "view_binding_conflict: reload the current binding and prepare again",
        ));
    }
    Ok(())
}
fn mutation_shape(args: &Value) -> Result<()> {
    let fields: &[&str] = match text(args, "action")? {
        "record_view_revision" => &["action", "id", "definition", "idempotency_key", "reason"],
        "activate_view" => &[
            "action",
            "id",
            "pin",
            "name",
            "expected_binding_event_id",
            "idempotency_key",
            "reason",
        ],
        "unpublish_view" => &[
            "action",
            "id",
            "expected_binding_event_id",
            "idempotency_key",
            "reason",
        ],
        _ => return Err(Error::engine("unsupported named view mutation")),
    };
    allowed(args, fields)?;
    if record_id(args)?.is_empty() {
        return Err(Error::engine("view bearer id required"));
    }
    let key = text(args, "idempotency_key")?.trim();
    if key.is_empty() || key.len() > 200 {
        return Err(Error::engine("idempotency_key must be 1..200 bytes"));
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) struct PreparedCommit {
    fingerprint: String,
    evidence: Option<Value>,
    deadline: Instant,
}
tokio::task_local! { static PREVALIDATED: PreparedCommit; }
#[cfg(test)]
tokio::task_local! { static EVICT_BEFORE_COMMIT: (); }
#[cfg(test)]
pub(crate) async fn with_evicted_validation<T>(work: impl std::future::Future<Output = T>) -> T {
    EVICT_BEFORE_COMMIT.scope((), work).await
}

// Independent of task-local proof/trace propagation: a dispatch that loses
// both must still expose any second preparation in the regression fixture.
#[cfg(test)]
type PreparationCounts = std::sync::Mutex<BTreeMap<(std::path::PathBuf, String), usize>>;
#[cfg(test)]
fn preparation_counts() -> &'static PreparationCounts {
    static COUNTS: std::sync::OnceLock<PreparationCounts> = std::sync::OnceLock::new();
    COUNTS.get_or_init(Default::default)
}
#[cfg(test)]
fn preparation_key(db: &Db, args: &Value) -> (std::path::PathBuf, String) {
    (
        db.path().to_owned(),
        format!("{}:{}", args["action"], args["idempotency_key"]),
    )
}
#[cfg(test)]
pub(crate) fn preparation_count(db: &Db, args: &Value) -> usize {
    preparation_counts()
        .lock()
        .unwrap()
        .get(&preparation_key(db, args))
        .copied()
        .unwrap_or(0)
}

#[cfg(test)]
tokio::task_local! { static COMMIT_TRACE: std::sync::Mutex<Vec<&'static str>>; }
#[cfg(test)]
pub(crate) fn note_commit_phase(phase: &'static str) {
    let _ = COMMIT_TRACE.try_with(|trace| trace.lock().unwrap().push(phase));
}
#[cfg(test)]
pub(crate) async fn trace_commit<T>(
    work: impl std::future::Future<Output = T>,
) -> (T, Vec<&'static str>) {
    COMMIT_TRACE
        .scope(std::sync::Mutex::new(Vec::new()), async {
            let result = work.await;
            let trace = COMMIT_TRACE.with(|trace| trace.lock().unwrap().clone());
            (result, trace)
        })
        .await
}

pub(crate) async fn with_prevalidated<T>(
    prepared: PreparedCommit,
    work: impl std::future::Future<Output = T>,
) -> T {
    PREVALIDATED.scope(prepared, work).await
}

/// Fresh SQLite work finishes on a read snapshot, before either commit guard.
/// The transaction re-resolves the exact closure and compares this request-local
/// proof. Cache eviction can never cause a worker wait while holding a writer.
pub(crate) async fn prepare_commit(
    db: &Db,
    actor: &str,
    caller: &crate::mcp::Caller,
    args: &Value,
) -> Result<PreparedCommit> {
    #[cfg(test)]
    {
        note_commit_phase("prepare");
        *preparation_counts()
            .lock()
            .unwrap()
            .entry(preparation_key(db, args))
            .or_default() += 1;
    }
    gate::require()?;
    mutation_shape(args)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let fingerprint = intent_fingerprint("manage_named_views", args.clone(), Value::Null)?;
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    kernel::kernel_require(
        &mut tx,
        actor,
        record_id(args)?,
        if publication(args) {
            Capability::View
        } else {
            Capability::Edit
        },
    )
    .await?;
    let ledger: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE type='table' AND name='kernel_mcp_write_receipts')").fetch_one(&mut *tx).await?;
    let old: bool = if ledger {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_mcp_write_receipts WHERE principal_id=? AND operation=? AND operation_key=?)")
            .bind(actor).bind(format!("manage_named_views.{}",text(args,"action")?)).bind(text(args,"idempotency_key")?.trim()).fetch_one(&mut *tx).await?
    } else {
        false
    };
    // Receipt identity includes the dispatched app and is checked under the
    // real dispatch context in the writer. Preflight carries schema proof only.
    let evidence = if old {
        None
    } else {
        Some(validate_on(&mut tx, actor, args, deadline, caller, None).await?)
    };
    tx.rollback().await?;
    Ok(PreparedCommit {
        fingerprint,
        evidence,
        deadline,
    })
}
async fn analyze_before_commit(
    plan: &closure::Closure,
    deadline: Instant,
    prepared: Option<&Value>,
) -> Result<()> {
    if let Some(proof) = prepared {
        if proof["analysis_digest"].as_str() != Some(plan.digest.as_str()) {
            return Err(Error::conflict("view_validation_changed: prepare again"));
        }
        return Ok(());
    }
    crate::query::sql::view_validation::analyze(plan, deadline).await?;
    Ok(())
}

async fn validate_on(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    args: &Value,
    deadline: Instant,
    caller: &crate::mcp::Caller,
    prepared: Option<&Value>,
) -> Result<Value> {
    mutation_shape(args)?;
    let id = record_id(args)?;
    authority_on(tx, actor, id, publication(args), caller).await?;
    let head: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
        .fetch_one(&mut *tx)
        .await?;
    let mut state = views::load_prefix(tx, head, deadline).await?;
    if state.legacy {
        return Err(Error::engine(
            "view_legacy_format: re-author retained revisions",
        ));
    }
    let current_name = state
        .bindings
        .get(&format!("native.named-view:{id}"))
        .and_then(|b| b.active.as_ref())
        .map(|(name, _)| name);
    let mut evidence = json!({"current_name":current_name});
    match text(args, "action")? {
        "record_view_revision" => {
            let definition: contract::Definition =
                serde_json::from_value(args["definition"].clone())?;
            if !matches!(definition.origin, contract::Origin::Authored) {
                return Err(Error::engine("generated revision authoring is reserved"));
            }
            definition.validate_for_preparation()?;
            let mut revision = Revision {
                v: 1,
                view_id: format!("native.named-view:{id}"),
                definition_sha256: String::new(),
                definition: serde_json::to_value(&definition)?,
            };
            revision.definition_sha256 = revision.digest();
            let event_id = prepared
                .and_then(|e| e["event_id"].as_str())
                .map(str::to_owned)
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let pin = Pin {
                view_id: revision.view_id.clone(),
                revision_id: event_id.clone(),
                definition_sha256: revision.definition_sha256.clone(),
                schema_sha256: definition.query.output.schema_sha256.clone(),
            };
            if serde_json::to_vec(&revision)?.len() > views::MAX_CARRIER_BYTES {
                return Err(Error::engine("view_budget_exceeded: revision carrier"));
            }
            let plan =
                closure::resolve_candidate_on(tx, actor, pin.clone(), definition, deadline).await?;
            analyze_before_commit(&plan, deadline, prepared).await?;
            evidence["analysis_digest"] = json!(plan.digest);
            if serde_json::to_vec(&json!({"pin":pin,"definition":plan.nodes.last().unwrap().definition,"closure_digest":plan.digest}))?.len()>256*1024 {return Err(Error::engine("view_budget_exceeded: revision response"));}
            evidence["event_id"] = json!(event_id);
            evidence["pin"] = json!(pin);
            evidence["payload"] = serde_json::to_value(revision)?;
        }
        "activate_view" => {
            check_cas(&state, args, id)?;
            let name = text(args, "name")?;
            contract::authored_name(name)?;
            let pin = exact(args)?;
            if pin.view_id != format!("native.named-view:{id}") {
                return Err(Error::engine("view_revision_unavailable"));
            }
            let plan = closure::resolve_on(
                tx,
                actor,
                &BTreeMap::from([(name.into(), pin.clone())]),
                deadline,
            )
            .await?;
            analyze_before_commit(&plan, deadline, prepared).await?;
            evidence["analysis_digest"] = json!(plan.digest);
            evidence["pin"] = json!(pin);
            evidence["payload"] = serde_json::to_value(Transition {
                v: 1,
                view_id: format!("native.named-view:{id}"),
                expected: expected(args)?,
                action: Action::Activate {
                    name: name.into(),
                    pin,
                },
            })?;
        }
        "unpublish_view" => {
            check_cas(&state, args, id)?;
            if state
                .bindings
                .get(&format!("native.named-view:{id}"))
                .and_then(|b| b.active.as_ref())
                .is_none()
            {
                return Err(Error::engine(
                    "view_binding_inactive: no active publication to remove",
                ));
            }
            evidence["payload"] = serde_json::to_value(Transition {
                v: 1,
                view_id: format!("native.named-view:{id}"),
                expected: expected(args)?,
                action: Action::Unpublish,
            })?;
        }
        _ => return Err(Error::engine("unsupported named view mutation")),
    }
    let kind = if args["action"] == "record_view_revision" {
        REVISION
    } else {
        TRANSITION
    };
    let event_id = evidence["event_id"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let proposed = crate::events::EventRow {
        local_seq: head + 1,
        id: event_id.clone(),
        record_id: id.into(),
        event_type: kind.into(),
        actor: Some(actor.into()),
        payload: Some(serde_json::to_string(&evidence["payload"])?),
        run_key: None,
        parent_key: None,
        intent: None,
        created_at: String::new(),
        causal_envelope: crate::events::CausalEnvelopeV1::legacy_unknown(),
        act: None,
    };
    state.apply(&proposed)?;
    evidence["event_id"] = json!(event_id);
    // Bind approval to this namespace transition, rather than
    // invalidate it on unrelated workspace writes. Live permissions, source
    // contracts, collisions and slots are rechecked at preparation and commit.
    let predecessor = if publication(args) {
        expected(args)?
    } else {
        None
    };
    use sha2::{Digest, Sha256};
    let digest = hex::encode(Sha256::digest(serde_json::to_vec(&json!([
        id,
        predecessor
    ]))?));
    evidence["state_digest"] = json!(digest);
    Ok(evidence)
}

pub(crate) async fn preview(
    db: &Db,
    actor: &str,
    caller: &crate::mcp::Caller,
    args: &Value,
) -> Result<Value> {
    gate::require()?;
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    let evidence = validate_on(
        &mut tx,
        actor,
        args,
        Instant::now() + Duration::from_secs(2),
        caller,
        None,
    )
    .await?;
    tx.rollback().await?;
    Ok(evidence)
}

pub(super) async fn execute(
    db: &Db,
    actor: &str,
    caller: &crate::mcp::Caller,
    args: Value,
) -> Result<Value> {
    gate::require()?;
    if db.open_mode() != crate::db::DatabaseOpenMode::ReadWrite {
        return Err(Error::engine(
            "view_profile_unsupported: named view operations require the hosted writer",
        ));
    }
    let action = text(&args, "action")?;
    match action {
        "get_view_revision" | "list_view_revisions" => {
            allowed(
                &args,
                if action == "get_view_revision" {
                    &["action", "view_id", "revision_id"]
                } else {
                    &["action", "view_id", "limit", "cursor"]
                },
            )?;
            let mut tx = db.pool().begin().await?;
            kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
            let deadline = Instant::now() + Duration::from_secs(2);
            let view = text(&args, "view_id")?;
            let result = if action == "get_view_revision" {
                views::details::get_on(&mut tx, actor, view, text(&args, "revision_id")?, deadline)
                    .await?
            } else {
                let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(8);
                views::details::list_on(
                    &mut tx,
                    actor,
                    view,
                    usize::try_from(limit).map_err(|_| Error::engine("invalid revision limit"))?,
                    optional_text(&args, "cursor")?,
                    deadline,
                )
                .await?
            };
            tx.rollback().await?;
            return Ok(result);
        }
        "prepare_named_views" => {
            allowed(&args, &["action"])?;
            let mut tx = begin_write(db.write_pool()).await?;
            kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
            kernel::kernel_require(
                &mut tx,
                actor,
                crate::events::KERNEL_ROOT_ID,
                Capability::Manage,
            )
            .await?;
            let installed = views::storage::ensure_index_on(&mut tx).await?;
            tx.commit().await?;
            return Ok(
                json!({"prepared":true,"already_prepared":installed,"optional_index":"idx_kernel_named_view_lifecycle"}),
            );
        }
        "record_view_revision" | "activate_view" | "unpublish_view" => {}
        _ => return Err(Error::engine("unknown named view operation")),
    }
    mutation_shape(&args)?;
    let key = text(&args, "idempotency_key")?.trim();
    if key.is_empty() || key.len() > 200 {
        return Err(Error::engine("idempotency_key must be 1..200 bytes"));
    }
    let prepared = match PREVALIDATED.try_with(Clone::clone) {
        Ok(prepared) => prepared,
        Err(_) => prepare_commit(db, actor, caller, &args).await?,
    };
    if prepared.fingerprint != intent_fingerprint("manage_named_views", args.clone(), Value::Null)?
    {
        return Err(Error::conflict("view_validation_changed: request changed"));
    }
    let deadline = prepared.deadline;
    views::storage::check_deadline(deadline)?;
    #[cfg(test)]
    if EVICT_BEFORE_COMMIT.try_with(|_| ()).is_ok() {
        if let Some(digest) = prepared
            .evidence
            .as_ref()
            .and_then(|e| e["analysis_digest"].as_str())
        {
            crate::query::sql::view_validation::evict_cache_entry(digest);
        }
    }
    let mut tx = begin_write(db.write_pool()).await?;
    let work = async {
        kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
        let id = record_id(&args)?;
        // Recheck current access before a prior success; replay creates no publication effect.
        kernel::kernel_require(
            &mut tx,
            actor,
            id,
            if publication(&args) {
                Capability::View
            } else {
                Capability::Edit
            },
        )
        .await?;
        // The established adapter ledger is optional and normalized out of coordinates.
        sqlx::query(RECEIPTS).execute(&mut *tx).await?;
        let fingerprint = dispatched_fingerprint("manage_named_views", args.clone())?;
        let old:Option<(String,String)>=sqlx::query_as("SELECT request_json,receipt_json FROM kernel_mcp_write_receipts WHERE principal_id=? AND operation=? AND operation_key=?").bind(actor).bind(format!("manage_named_views.{action}")).bind(key).fetch_optional(&mut *tx).await?;
        if let Some((request, raw)) = old {
            if stored_fingerprint("manage_named_views", serde_json::from_str(&request)?)?
                != fingerprint
            {
                return Err(Error::conflict(
                    "idempotency_key reused for a different view request",
                ));
            }
            let mut receipt: Value = serde_json::from_str(&raw)?;
            if let Some(pin) = receipt.get("pin").filter(|_| action != "unpublish_view") {
                let pin: Pin = serde_json::from_value(pin.clone())?;
                closure::inspect_metadata_on(
                    &mut tx,
                    actor,
                    &BTreeMap::from([("view_retry".into(), pin)]),
                    deadline,
                )
                .await?;
            }
            receipt["replayed"] = json!(true);
            tx.rollback().await?;
            return Ok(receipt);
        }
        let proof = prepared
            .evidence
            .as_ref()
            .ok_or_else(|| Error::conflict("view receipt changed: retry the original request"))?;
        #[cfg(test)]
        let builds_before = crate::query::sql::view_validation::builds(
            proof["analysis_digest"].as_str().unwrap_or_default(),
        );
        let evidence = validate_on(&mut tx, actor, &args, deadline, caller, Some(proof)).await?;
        #[cfg(test)]
        if EVICT_BEFORE_COMMIT.try_with(|_| ()).is_ok() {
            assert_eq!(
                crate::query::sql::view_validation::builds(
                    proof["analysis_digest"].as_str().unwrap_or_default()
                ),
                builds_before,
                "no validator worker may start under the workspace writer or owner guard"
            );
        }
        let mut acts = ActAllocation::new();
        use sha2::{Digest, Sha256};
        let pending = kernel::app_installs::start_app_action_in(
            db,
            &mut tx,
            actor,
            "manage_named_views",
            hex::encode(Sha256::digest(fingerprint.as_bytes())),
            optional_text(&args, "reason")?.map(str::to_owned),
            &mut acts,
        )
        .await?;
        let kind = if action == "record_view_revision" {
            REVISION
        } else {
            TRANSITION
        };
        let event_id = text(&evidence, "event_id")?.to_owned();
        crate::store::append_with_event_id_in(
            db,
            &mut tx,
            event_id.clone(),
            AppendSpec {
                record_id: id.into(),
                event_type: kind.into(),
                payload: evidence["payload"].clone(),
                actor: Some(actor.into()),
            },
            &mut acts,
        )
        .await?;
        let mut receipt = json!({"id":id,"operation":action,"event_id":event_id,"replayed":false,"write_receipt":{"kind":"kernel_content_event","event_id":event_id}});
        if let Some(pin) = evidence.get("pin") {
            receipt["pin"] = pin.clone();
        }
        if kind == TRANSITION {
            receipt["binding_event_id"] = json!(event_id);
        }
        if let Some(app) =
            kernel::app_installs::finish_app_action_in(db, &mut tx, actor, pending, &mut acts)
                .await?
        {
            receipt["app_attribution"] = app;
        }
        // A lifecycle write also advances its bearer's record revision. Refuse
        // a source contract that this very operation would invalidate, before
        // either the event or its retry receipt can commit.
        if let Some(pin) = receipt.get("pin").filter(|_| action != "unpublish_view") {
            let pin: Pin = serde_json::from_value(pin.clone())?;
            closure::resolve_on(
                &mut tx,
                actor,
                &BTreeMap::from([("view_committed".into(), pin)]),
                deadline,
            )
            .await?;
        }
        sqlx::query("INSERT INTO kernel_mcp_write_receipts VALUES(?,?,?,?,?)")
            .bind(actor)
            .bind(format!("manage_named_views.{action}"))
            .bind(key)
            .bind(fingerprint)
            .bind(serde_json::to_string(&receipt)?)
            .execute(&mut *tx)
            .await?;
        views::storage::check_deadline(deadline)?;
        db.commit_kernel_content(tx).await?;
        Ok(receipt)
    };
    gate::scope(deadline, work).await
}

/// The shared executor can replay a terminal plan without calling its source.
/// Recheck bearer access, and closure visibility for activation. Unpublish
/// replay has no definition payload and only requires current bearer View.
pub(crate) async fn authorize_retry(
    db: &Db,
    actor: &str,
    args: &Value,
    _completed: bool,
) -> Result<()> {
    gate::require()?;
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    kernel::kernel_require(&mut tx, actor, record_id(args)?, Capability::View).await?;
    if args["action"] == "activate_view" {
        closure::inspect_metadata_on(
            &mut tx,
            actor,
            &BTreeMap::from([("view_retry".into(), exact(args)?)]),
            Instant::now() + Duration::from_secs(2),
        )
        .await?;
    }
    tx.rollback().await?;
    Ok(())
}
