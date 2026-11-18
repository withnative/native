//! Dependency-graph batch creation on KernelV2.
//!
//! This adapter mirrors the v1 `create_many` contract (partial success,
//! positional receipts, failed-dependant suppression, summary/verbose modes)
//! over v2 storage. The pure graph planning — local-ref preflight, cycle
//! checking, topological ordering and body-ref substitution — is shared with
//! v1 without change; only visibility was widened, no logic.
//!
//! Two v2 differences shape the rest:
//!
//! - **V2 mints record ids.** Caller-supplied `id` and `owner_id` are refused
//!   at preflight with a clear message. The shared planner still reserves
//!   fresh random placeholder ids per attempt for graph resolution, but they
//!   are stripped before dispatch and rebound to the actual minted ids as
//!   work proceeds in topological order. Placeholders are never persisted,
//!   never derived from the batch key, and never cross a database boundary,
//!   per the prohibition behind Native 7da1844.
//! - **Keyed replay follows A2 (Native 10ca9e2).** One key covers the call;
//!   each item commits under its own identity, `sha256({create_many_key,
//!   item})`, as a lookup key in the v2 keyed-outcome ledger — never as a
//!   record id. There is no whole-call anchor: a failed item leaves no row,
//!   so a retry resumes it. Before any item runs, every stored per-item row
//!   for the key is compared against the whole-call fingerprint, so changed
//!   arguments — including changed length and previously failed items — are
//!   refused up front. A replay re-proves current authority and confers
//!   nothing after revocation.
//!
//! V1 storage handlers are never called against v2.
use super::*;
use crate::mcp::tools::create_many::{
    preflight, rebind_dependencies, topological_order, PreparedRecord, MAX_CREATE_MANY,
};

const TOOL: &str = "create_many";
/// Ledger operation for per-item keyed rows. Whole-call rows are never
/// stored: partial attempts must resume, not replay as complete.
const ITEM_OPERATION: &str = "create_many";

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResponseMode {
    Summary,
    Verbose,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ItemState {
    Pending,
    Succeeded,
    Failed,
}

/// One item's ledger identity: the call's key bound to the item index. This
/// is a lookup key only. It is hashed so the raw key never lands in the
/// ledger twice, matching the v1 A2 identity shape.
fn item_command_identity(key: &str, index: usize) -> String {
    crate::provenance::digest_json(&json!({"create_many_key": key, "item": index}))
}

pub(super) async fn execute(db: &Db, actor: &str, raw: Value) -> Result<Value> {
    let args = object(&raw)?.clone();
    // Field-only key validation: the shared `allowed` helper also pins
    // response_mode to `full`, which would make this tool's own
    // summary/verbose modes unreachable.
    for key in args.keys() {
        if !["reason", "records", "response_mode", "idempotency_key"].contains(&key.as_str()) {
            return Err(invalid(format!("unsupported argument {key}")));
        }
    }
    let reason = text(&raw, "reason")?;
    if reason.trim().is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: 'reason' must contain non-whitespace reasoning"
        )));
    }
    let records = args
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(format!("{TOOL}: records must be an array")))?;
    if records.is_empty() {
        return Err(invalid(format!(
            "{TOOL}: records must contain at least one item"
        )));
    }
    if records.len() > MAX_CREATE_MANY {
        return Err(invalid(format!(
            "{TOOL}: at most {MAX_CREATE_MANY} records may be created per call"
        )));
    }
    let response_mode = match args.get("response_mode") {
        None | Some(Value::Null) => ResponseMode::Summary,
        Some(Value::String(mode)) if mode == "summary" => ResponseMode::Summary,
        Some(Value::String(mode)) if mode == "verbose" => ResponseMode::Verbose,
        _ => {
            return Err(invalid(format!(
                "{TOOL}: response_mode must be summary or verbose"
            )));
        }
    };
    // Typed key parsing: a malformed non-string key must refuse, never
    // silently degrade into an unkeyed write.
    let key = crate::mcp::tools::keyed_replay::idempotency_key(
        TOOL,
        optional_text(&raw, "idempotency_key")?,
    )?;
    let mut maps = Vec::with_capacity(records.len());
    for (index, record) in records.iter().enumerate() {
        let map = record
            .as_object()
            .ok_or_else(|| invalid(format!("{TOOL}: records[{index}] must be an object")))?;
        if map.contains_key("id") {
            return Err(invalid(format!(
                "{TOOL}: records[{index}].id is not supported; v2 mints record ids — omit it"
            )));
        }
        if map.contains_key("owner_id") {
            return Err(invalid(format!(
                "{TOOL}: records[{index}].owner_id is not supported on v2; omit it"
            )));
        }
        maps.push(map.clone());
    }
    let prepared = preflight(maps, reason)?;
    let order = topological_order(&prepared)?;
    // Whole-call fingerprint over the caller's arguments. Response
    // representation and per-item confirm are not part of the governed
    // command — a retry may change verbosity without becoming a conflict —
    // while every record, in order, is: length and failed-item edits refuse.
    let mut fingerprinted = raw.clone();
    if let Some(object) = fingerprinted.as_object_mut() {
        object.remove("response_mode");
        if let Some(records) = object.get_mut("records").and_then(Value::as_array_mut) {
            for record in records.iter_mut() {
                if let Some(object) = record.as_object_mut() {
                    object.remove("confirm");
                }
            }
        }
    }
    let fingerprint = dispatched_fingerprint(TOOL, fingerprinted)?;
    if let Some(key) = key.as_deref() {
        refuse_reused_key(db, actor, key, &fingerprint).await?;
    }
    execute_call(
        db,
        actor,
        prepared,
        order,
        response_mode,
        key.as_deref(),
        &fingerprint,
    )
    .await
}

/// Refuse a key this caller already used with different records before any
/// item runs. Every stored per-item row for the key carries the whole-call
/// fingerprint, so this covers changed length and previously failed items as
/// well as reordered or edited ones. It reads only the caller's own rows and
/// discloses no record.
async fn refuse_reused_key(db: &Db, actor: &str, key: &str, fingerprint: &str) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    sqlx::query(RECEIPTS).execute(&mut *tx).await?;
    let refused = check_key_shape(&mut tx, actor, key, fingerprint).await;
    tx.rollback().await?;
    refused
}

/// Compare every stored per-item row for the key against the whole-call
/// fingerprint. This runs up front before any item, and again inside each
/// item's serialized transaction: without the second check, two different
/// shapes racing under one key could each store their own index and produce
/// a mixed batch. Read-only; it stores no whole-call anchor.
async fn check_key_shape(
    tx: &mut SqliteConnection,
    actor: &str,
    key: &str,
    fingerprint: &str,
) -> Result<()> {
    for index in 0..MAX_CREATE_MANY {
        kernel::mcp_write_receipts::fences::refuse_key_on(
            tx,
            actor,
            ITEM_OPERATION,
            &item_command_identity(key, index),
        )
        .await?;
        let old: Option<(String,)> = sqlx::query_as("SELECT request_json FROM kernel_mcp_write_receipts WHERE principal_id=? AND operation=? AND operation_key=?")
            .bind(actor)
            .bind(ITEM_OPERATION)
            .bind(item_command_identity(key, index))
            .fetch_optional(&mut *tx)
            .await?;
        if let Some((old,)) = old {
            if old != fingerprint {
                return Err(Error::conflict(
                    "idempotency_key reused for different request",
                ));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn execute_call(
    db: &Db,
    actor: &str,
    records: Vec<PreparedRecord>,
    order: Vec<usize>,
    response_mode: ResponseMode,
    key: Option<&str>,
    fingerprint: &str,
) -> Result<Value> {
    let mut states = vec![ItemState::Pending; records.len()];
    let mut ids = vec![Value::Null; records.len()];
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut body_digests = Vec::new();
    let mut verbose_results = Vec::new();
    let mut acts = Vec::new();
    for index in order {
        let record = &records[index];
        let failed_dependencies = record
            .dependencies
            .iter()
            .copied()
            .filter(|dependency| states[*dependency] == ItemState::Failed)
            .collect::<Vec<_>>();
        if !failed_dependencies.is_empty() {
            states[index] = ItemState::Failed;
            errors.push(item_error(
                record,
                "dependency_failed",
                format!("creation depends on failed record indexes {failed_dependencies:?}"),
                Some(failed_dependencies),
            ));
            continue;
        }
        if record.arguments.get("type").and_then(Value::as_str) == Some("Message") {
            states[index] = ItemState::Failed;
            errors.push(item_error(
                record,
                "unsupported_record_type",
                "Message creation is not supported by create_many; use create_record for a draft or manage_messages.send for delivery".into(),
                None,
            ));
            continue;
        }
        let mut arguments = record.arguments.clone();
        let rebound = record
            .dependencies
            .iter()
            .filter_map(|dependency| {
                let reserved = records[*dependency].arguments.get("id")?.as_str()?;
                let actual = ids[*dependency].as_str()?;
                (reserved != actual).then_some((reserved, actual))
            })
            .collect::<Vec<_>>();
        rebind_dependencies(&mut arguments, &rebound);
        // V2 mints record ids: the shared planner's per-attempt placeholder
        // never reaches storage. Dependants above were already rebound to the
        // actual minted ids of their replayed or freshly created dependencies.
        if let Some(object) = arguments.as_object_mut() {
            object.remove("id");
        }
        let materialized_body = arguments
            .get("body")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| record.materialized_body.clone());
        match create_keyed_item(db, actor, arguments, key, index, fingerprint).await {
            Ok(created) => {
                states[index] = ItemState::Succeeded;
                let id = created
                    .get("id")
                    .and_then(Value::as_str)
                    .expect("v2 create success carries id")
                    .to_owned();
                ids[index] = Value::String(id.clone());
                if let Some(act) = created.get("act").and_then(Value::as_i64) {
                    acts.push(json!({ "index": index, "id": id, "act": act }));
                }
                if let Some(body) = &materialized_body {
                    if let Some(digest) = created.get("body_digest").and_then(Value::as_str) {
                        body_digests.push(json!({
                            "index": index,
                            "id": id,
                            "sha256": digest,
                            "chars": body.chars().count(),
                            "bytes": body.len(),
                        }));
                    }
                }
                for warning in created
                    .get("warnings")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let mut wrapped = match warning.as_object() {
                        Some(warning) => Value::Object(warning.clone()),
                        None => json!({"warning": warning}),
                    };
                    wrapped["index"] = json!(index);
                    if let Some(local_ref) = &record.local_ref {
                        wrapped["ref"] = json!(local_ref);
                    }
                    warnings.push(wrapped);
                }
                if response_mode == ResponseMode::Verbose {
                    verbose_results.push(json!({
                        "index": index,
                        "ref": record.local_ref,
                        "status": "created",
                        "record": created,
                    }));
                }
            }
            Err(error) => {
                states[index] = ItemState::Failed;
                errors.push(item_error(record, "create_failed", error.to_string(), None));
            }
        }
    }
    let mut result = json!({
        "ok": errors.is_empty(),
        "ids": ids,
    });
    errors.sort_by_key(|error| error["index"].as_u64().unwrap_or_default());
    warnings.sort_by_key(|warning| warning["index"].as_u64().unwrap_or_default());
    body_digests.sort_by_key(|digest| digest["index"].as_u64().unwrap_or_default());
    let object = result.as_object_mut().expect("create_many receipt object");
    if !errors.is_empty() {
        object.insert("errors".into(), Value::Array(errors));
    }
    if !warnings.is_empty() {
        object.insert("warnings".into(), Value::Array(warnings));
    }
    if !body_digests.is_empty() {
        object.insert("body_digests".into(), Value::Array(body_digests));
    }
    if response_mode == ResponseMode::Verbose {
        verbose_results.sort_by_key(|result| result["index"].as_u64().unwrap_or_default());
        object.insert("results".into(), Value::Array(verbose_results));
    } else if !acts.is_empty() {
        acts.sort_by_key(|entry| entry["index"].as_u64().unwrap_or_default());
        object.insert("acts".into(), Value::Array(acts));
    }
    Ok(result)
}

/// Create, or replay, one item of a keyed call. Unkeyed items always create.
/// The lookup and the mutation share one serialized transaction: a concurrent
/// call with the same key blocks on `BEGIN IMMEDIATE`, then sees this item's
/// row and replays instead of duplicating it.
async fn create_keyed_item(
    db: &Db,
    actor: &str,
    arguments: Value,
    key: Option<&str>,
    index: usize,
    fingerprint: &str,
) -> Result<Value> {
    let Some(key) = key else {
        let mut tx = begin_write(db.write_pool()).await?;
        kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
        let mut acts = ActAllocation::new();
        let created = create_item_in(db, &mut tx, &mut acts, actor, &arguments).await;
        match created {
            Ok(created) => {
                db.commit_kernel_content(tx).await?;
                return Ok(created);
            }
            Err(error) => {
                tx.rollback().await?;
                return Err(error);
            }
        }
    };
    let identity = item_command_identity(key, index);
    let mut tx = begin_write(db.write_pool()).await?;
    kernel::mcp_write_receipts::fences::refuse_key_on(&mut tx, actor, ITEM_OPERATION, &identity)
        .await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    sqlx::query(RECEIPTS).execute(&mut *tx).await?;
    // Recheck every stored identity inside this serialized transaction, so
    // another shape that committed between the upfront check and this item
    // cannot produce a mixed batch.
    if let Err(error) = check_key_shape(&mut tx, actor, key, fingerprint).await {
        tx.rollback().await?;
        return Err(error);
    }
    let old: Option<(String, String)> = sqlx::query_as("SELECT request_json,receipt_json FROM kernel_mcp_write_receipts WHERE principal_id=? AND operation=? AND operation_key=?")
        .bind(actor)
        .bind(ITEM_OPERATION)
        .bind(&identity)
        .fetch_optional(&mut *tx)
        .await?;
    if let Some((old_request, receipt_raw)) = old {
        if old_request != fingerprint {
            tx.rollback().await?;
            return Err(Error::conflict(
                "idempotency_key reused for different request",
            ));
        }
        let stored: Value = serde_json::from_str(&receipt_raw)?;
        let id = stored
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("stored create_many receipt has no id"))?
            .to_owned();
        let targets = stored
            .get("link_targets")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        // Replay confers nothing after revocation or a move: re-prove current
        // authority before disclosing the stored shape. The record itself is
        // always re-proved for View; creation authority is Edit, except a
        // comment, which authorizes on its bearer and re-proves bearer View.
        kernel::kernel_require(&mut tx, actor, &id, Capability::View).await?;
        let bearers = kernel::comments_v2::bearer_on(&mut tx, &id).await?;
        if bearers.is_empty() {
            kernel::kernel_require(&mut tx, actor, &id, Capability::Edit).await?;
        } else {
            for bearer in &bearers {
                kernel::kernel_require(&mut tx, actor, bearer, Capability::View).await?;
            }
        }
        for target in targets.iter().filter_map(Value::as_str) {
            kernel::kernel_require(&mut tx, actor, target, Capability::View).await?;
        }
        let created = stored
            .get("record")
            .cloned()
            .ok_or_else(|| invalid("stored create_many receipt has no record"))?;
        tx.rollback().await?;
        return Ok(created);
    }
    let mut acts = ActAllocation::new();
    let created = create_item_in(db, &mut tx, &mut acts, actor, &arguments).await;
    match created {
        Ok(created) => {
            let id = created
                .get("id")
                .and_then(Value::as_str)
                .expect("v2 create success carries id");
            let targets = created
                .get("link_targets")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            kernel::mcp_write_receipts::record_on(
                db,
                &mut tx,
                &mut acts,
                kernel::mcp_write_receipts::Outcome {
                    principal: actor,
                    operation: ITEM_OPERATION,
                    key: &identity,
                    request: fingerprint,
                    receipt: &serde_json::to_string(&json!({
                        "id": id,
                        "link_targets": targets,
                        "record": created,
                    }))?,
                },
            )
            .await?;
            db.commit_kernel_content(tx).await?;
            Ok(created)
        }
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}

/// One item's mutation inside its own transaction. Each item is an ordinary
/// v2 `create_record` act, so items do not share a write: a failure rolls
/// back only its own transaction.
async fn create_item_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut ActAllocation,
    actor: &str,
    args: &Value,
) -> Result<Value> {
    use sha2::{Digest, Sha256};
    let item_fingerprint = dispatched_fingerprint("create_record", args.clone())?;
    let pending = kernel::app_installs::start_app_action_in(
        db,
        tx,
        actor,
        "create_record",
        hex::encode(Sha256::digest(item_fingerprint.as_bytes())),
        optional_text(args, "reason")?.map(str::to_owned),
        acts,
    )
    .await?;
    let mut created = create(db, tx, acts, actor, args).await?;
    if let Some(attribution) =
        kernel::app_installs::finish_app_action_in(db, tx, actor, pending, acts).await?
    {
        created["app_attribution"] = attribution;
    }
    Ok(created)
}

fn item_error(
    record: &PreparedRecord,
    code: &str,
    message: String,
    dependency_indexes: Option<Vec<usize>>,
) -> Value {
    let mut error = json!({
        "index": record.index,
        "code": code,
        "message": message,
    });
    if let Some(local_ref) = &record.local_ref {
        error["ref"] = json!(local_ref);
    }
    if let Some(dependency_indexes) = dependency_indexes {
        error["dependency_indexes"] = json!(dependency_indexes);
    }
    error
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(super) fn item_command_identity_for_settlement_test(key: &str, index: usize) -> String {
    item_command_identity(key, index)
}
#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(super) async fn item_for_settlement_test(
    db: &Db,
    actor: &str,
    args: Value,
    key: &str,
    fingerprint: &str,
) -> Result<Value> {
    create_keyed_item(db, actor, args, Some(key), 0, fingerprint).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        events::KERNEL_ROOT_ID,
        mcp::{kernel_v2::tests::registry, registry::Caller},
    };

    struct World {
        _dir: tempfile::TempDir,
        db: Db,
        admin: String,
        viewer: String,
        home: String,
        private: String,
    }
    async fn world() -> World {
        let dir = tempfile::tempdir().unwrap();
        let (db, admin) = kernel::create_v2_database(
            dir.path().join("create-many.db").to_str().unwrap(),
            "account",
            "Admin",
            "acct:admin",
        )
        .await
        .unwrap();
        let viewer = kernel::create_principal(&db, "account", "Viewer", "acct:viewer", &admin)
            .await
            .unwrap();
        for manifest in [
            v1_compat::package(),
            crate::v2_standard::document4_package(),
            relation::package(),
        ] {
            let identity = manifest.identity().unwrap();
            kernel::install_package_as(&db, &admin, &manifest)
                .await
                .unwrap();
            kernel::adopt_package_at(
                &db,
                &admin,
                KERNEL_ROOT_ID,
                &manifest,
                Some(&identity),
                &manifest.declared_reads,
            )
            .await
            .unwrap();
        }
        let home = kernel::create_home(
            &db,
            KERNEL_ROOT_ID,
            Some(&[(&admin, "manage"), (&viewer, "view")]),
            &admin,
        )
        .await
        .unwrap();
        let private = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&admin, "manage")]), &admin)
            .await
            .unwrap();
        World {
            _dir: dir,
            db,
            admin,
            viewer,
            home,
            private,
        }
    }
    async fn call(w: &World, credential: &str, tool: &str, args: Value) -> Result<Value> {
        registry()
            .call_engine(
                EngineHandle::KernelV2(w.db.clone()),
                Caller::authenticated(credential),
                tool,
                args,
            )
            .await
    }
    async fn admin(w: &World, tool: &str, args: Value) -> Value {
        call(w, "acct:admin", tool, args).await.unwrap()
    }
    async fn count(w: &World) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap()
    }
    async fn record(w: &World, id: &str) -> kernel::KernelRecordView {
        kernel::read_record_as(&w.db, &w.admin, id)
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn create_many_graph_refs_bind_to_minted_ids() {
        let w = world().await;
        // The child comes first in input order: stable topological order must
        // still create the parent first and bind every ref to its minted id.
        let out = admin(
            &w,
            "create_many",
            json!({
                "reason": "fixture graph",
                "response_mode": "verbose",
                "records": [
                    {"ref": "child", "type": "Document", "kind": "note", "name": "Child",
                     "parent_ref": "folder", "body": "See [[folder]]",
                     "links": [{"target_ref": "folder", "relationship": "relates_to"}]},
                    {"ref": "folder", "type": "Collection", "kind": "folder", "name": "Folder", "home_id": w.home},
                ],
            }),
        )
        .await;
        assert_eq!(out["ok"], true);
        let child = out["ids"][0].as_str().unwrap().to_owned();
        let folder = out["ids"][1].as_str().unwrap().to_owned();
        assert_ne!(child, folder);
        // V2 mints every id: both are fresh random UUIDs, not caller inputs.
        assert!(uuid::Uuid::parse_str(&child).is_ok());
        assert!(uuid::Uuid::parse_str(&folder).is_ok());
        // The folder has a separate home for its children, resolved from
        // its canonical binding rather than the folder's own filing home.
        let child_home = {
            let mut conn = w.db.pool().acquire().await.unwrap();
            crate::v1_import::resolve_home_on_connection(&mut conn, &w.admin, &folder)
                .await
                .unwrap()
        };
        assert_eq!(record(&w, &child).await.home_id, child_home);
        assert_eq!(
            record(&w, &child).await.body.as_deref(),
            Some(format!("See [[{folder}]]").as_str())
        );
        let child_record = out["results"][0]["record"].clone();
        assert_eq!(child_record["id"], child);
        assert_eq!(child_record["link_targets"], json!([folder]));
        w.db.close().await;
    }

    #[tokio::test]
    async fn create_many_partial_failure_suppresses_dependants() {
        let w = world().await;
        let out = admin(
            &w,
            "create_many",
            json!({
                "reason": "fixture partial",
                "response_mode": "summary",
                "records": [
                    {"ref": "good", "type": "Document", "kind": "note", "name": "Keeps", "home_id": w.home},
                    {"ref": "bad", "type": "Document", "kind": "note", "name": "Bad home", "home_id": "missing"},
                    {"ref": "orphan", "type": "Document", "kind": "note", "name": "Orphan", "parent_ref": "bad"},
                    {"type": "Message", "kind": "draft", "name": "Nope"},
                    {"type": "Document", "kind": "note", "name": "Also keeps", "home_id": w.home},
                ],
            }),
        )
        .await;
        assert_eq!(out["ok"], false);
        assert!(out["ids"][0].as_str().is_some());
        assert_eq!(out["ids"][1], Value::Null);
        assert_eq!(out["ids"][2], Value::Null);
        assert_eq!(out["ids"][3], Value::Null);
        assert!(out["ids"][4].as_str().is_some());
        let errors = out["errors"].as_array().unwrap();
        assert_eq!(errors.len(), 3);
        assert_eq!(errors[0]["index"], 1);
        assert_eq!(errors[0]["code"], "create_failed");
        assert_eq!(errors[1]["index"], 2);
        assert_eq!(errors[1]["code"], "dependency_failed");
        assert_eq!(errors[1]["ref"], "orphan");
        assert_eq!(errors[1]["dependency_indexes"], json!([1]));
        assert_eq!(errors[2]["index"], 3);
        assert_eq!(errors[2]["code"], "unsupported_record_type");
        // App-less v2 create receipts carry act:null, so this receipt has
        // positional ids and errors without the supplementary acts array.
        assert!(out.get("acts").is_none());
        w.db.close().await;
    }

    #[tokio::test]
    async fn create_many_keyed_retry_resumes_and_refuses_changes() {
        let w = world().await;
        let args = json!({
            "reason": "fixture keyed",
            "idempotency_key": "batch-partial",
            "records": [
                {"ref": "a", "type": "Document", "kind": "note", "name": "A", "home_id": w.home},
                {"type": "Document", "kind": "note", "name": "Bad", "parent_ref": "a",
                 "links": [{"target_id": "missing", "relationship": "relates_to"}]},
            ],
        });
        let first = admin(&w, "create_many", args.clone()).await;
        assert_eq!(first["ok"], false);
        let replayed = first["ids"][0].clone();
        assert!(replayed.as_str().is_some());
        assert_eq!(first["ids"][1], Value::Null);
        // An identical retry resumes without duplicating the created item.
        let before = count(&w).await;
        let second = admin(&w, "create_many", args.clone()).await;
        assert_eq!(second["ok"], false);
        assert_eq!(second["ids"][0], replayed);
        assert_eq!(second["ids"][1], Value::Null);
        assert_eq!(count(&w).await, before);
        // Fixing the previously failed item is a different call: refused
        // before new writes, with nothing written.
        let mut fixed = args.clone();
        fixed["records"][1] =
            json!({"type": "Document", "kind": "note", "name": "Fixed", "parent_ref": "a"});
        let err = call(&w, "acct:admin", "create_many", fixed)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("different request"), "{err}");
        assert_eq!(count(&w).await, before);
        // Changed length is refused the same way.
        let mut grown = args.clone();
        grown["records"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type": "Document", "kind": "note", "name": "C", "home_id": w.home}));
        let err = call(&w, "acct:admin", "create_many", grown)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("different request"), "{err}");
        assert_eq!(count(&w).await, before);
        // A complete call replays byte-identical receipts.
        let good = json!({
            "reason": "fixture keyed complete",
            "idempotency_key": "batch-complete",
            "records": [
                {"ref": "a", "type": "Collection", "kind": "folder", "name": "A", "home_id": w.home},
                {"type": "Document", "kind": "note", "name": "B", "parent_ref": "a", "body": "child of [[a]]"},
            ],
        });
        let once = admin(&w, "create_many", good.clone()).await;
        assert_eq!(once["ok"], true, "{once}");
        let settled = count(&w).await;
        assert_eq!(admin(&w, "create_many", good.clone()).await, once);
        assert_eq!(count(&w).await, settled);
        w.db.close().await;
    }

    #[tokio::test]
    async fn create_many_malformed_key_refuses_without_writes() {
        let w = world().await;
        let before = count(&w).await;
        // A non-string key must refuse as malformed, never degrade into an
        // unkeyed write.
        let err = call(
            &w,
            "acct:admin",
            "create_many",
            json!({
                "reason": "fixture malformed key",
                "idempotency_key": 42,
                "records": [{"type": "Document", "kind": "note", "name": "Never", "home_id": w.home}],
            }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("must be a string"), "{err}");
        assert_eq!(count(&w).await, before);
        w.db.close().await;
    }

    #[tokio::test]
    async fn create_many_item_recheck_blocks_mixed_shapes() {
        let w = world().await;
        // One stored index under a key blocks another index's different
        // shape, deterministically: the per-item recheck compares every
        // stored identity against the calling shape inside the item's own
        // serialized transaction.
        // Stand-ins use the production fingerprint function, so they carry
        // the exact normalized envelope the ledger validates and stores.
        let fp_a = dispatched_fingerprint(TOOL, json!({"shape": "a"})).unwrap();
        let fp_b = dispatched_fingerprint(TOOL, json!({"shape": "b"})).unwrap();
        let first = create_keyed_item(
            &w.db,
            &w.admin,
            json!({"type": "Document", "kind": "note", "name": "First", "home_id": w.home, "reason": "fixture race"}),
            Some("race-key"),
            0,
            &fp_a,
        )
        .await
        .unwrap();
        assert!(first["id"].as_str().is_some());
        let before = count(&w).await;
        let err = create_keyed_item(
            &w.db,
            &w.admin,
            json!({"type": "Document", "kind": "note", "name": "Other", "home_id": w.home, "reason": "fixture race"}),
            Some("race-key"),
            1,
            &fp_b,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("different request"), "{err}");
        assert_eq!(count(&w).await, before);
        // The identical shape at another index still proceeds.
        let second = create_keyed_item(
            &w.db,
            &w.admin,
            json!({"type": "Document", "kind": "note", "name": "Other", "home_id": w.home, "reason": "fixture race"}),
            Some("race-key"),
            1,
            &fp_a,
        )
        .await
        .unwrap();
        assert_ne!(second["id"], first["id"]);
        w.db.close().await;
    }

    #[tokio::test]
    async fn create_many_replay_after_revocation_is_denied() {
        let w = world().await;
        kernel::replace_home_policy(
            &w.db,
            &w.admin,
            &w.private,
            &[(&w.admin, "manage"), (&w.viewer, "view")],
        )
        .await
        .unwrap();
        let target = admin(
            &w,
            "create_record",
            json!({"type": "WorkItem", "kind": "task", "name": "Target", "home_id": w.private, "reason": "fixture revoked"}),
        )
        .await["id"]
            .clone();
        kernel::replace_home_policy(
            &w.db,
            &w.admin,
            &w.home,
            &[(&w.admin, "manage"), (&w.viewer, "edit")],
        )
        .await
        .unwrap();
        let args = json!({
            "reason": "fixture revoked",
            "idempotency_key": "viewer-batch",
            "records": [{"type": "Document", "kind": "note", "name": "V", "home_id": w.home,
                         "links": [{"target_id": target, "relationship": "relates_to"}]}],
        });
        let first = call(&w, "acct:viewer", "create_many", args.clone())
            .await
            .unwrap();
        assert_eq!(first["ok"], true);
        let created = first["ids"][0].clone();
        // Revoking the filing home does not strip the creator's owner floor:
        // the identical retry still replays, without duplicating.
        kernel::replace_home_policy(&w.db, &w.admin, &w.home, &[(&w.admin, "manage")])
            .await
            .unwrap();
        let settled = count(&w).await;
        let replayed = call(&w, "acct:viewer", "create_many", args.clone())
            .await
            .unwrap();
        assert_eq!(replayed["ok"], true);
        assert_eq!(replayed["ids"][0], created);
        assert_eq!(count(&w).await, settled);
        // Revoking the linked target's home denies the replay: the stored
        // link target is re-proved for View and confers nothing after
        // revocation.
        kernel::replace_home_policy(&w.db, &w.admin, &w.private, &[(&w.admin, "manage")])
            .await
            .unwrap();
        let before = count(&w).await;
        let retry = call(&w, "acct:viewer", "create_many", args.clone())
            .await
            .unwrap();
        assert_eq!(retry["ok"], false);
        assert_eq!(retry["ids"][0], Value::Null);
        let message = retry["errors"][0]["message"].as_str().unwrap();
        assert!(message.contains(kernel::HIDDEN_OR_MISSING), "{message}");
        assert_eq!(count(&w).await, before);
        w.db.close().await;
    }
}
