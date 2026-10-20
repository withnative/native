//! Ordinary probe writes. The adapter receipt and every kernel event commit
//! together; a failed field/body/facet/link operation rolls back the whole act.
use super::{parse, principal};
use crate::{
    act::ActAllocation,
    authorization::Capability,
    db::{begin_write, Db},
    kernel,
    mcp::registry::{EngineHandle, EngineKind, ToolRegistry},
    store::{append_in, AppendSpec},
    v2_standard::{relates_to as relation, v1_compat},
    Error, Result,
};
use serde_json::{json, Map, Value};
use sqlx::{Sqlite, Transaction};

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    for tool in [
        "attach_text",
        "create_record",
        "update_record",
        "manage_links",
        "archive_record",
    ] {
        registry.register_engine_handler(
            tool,
            EngineKind::KernelV2,
            move |engine, caller, args| async move {
                let EngineHandle::KernelV2(db) = engine else {
                    unreachable!()
                };
                let actor = principal(&db, &caller).await?;
                execute(&db, &actor, tool, args).await
            },
        )?;
    }
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
        if !keys.contains(&key.as_str()) {
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

// Durable adapter state, deliberately independent of rebuildable kernel
// projections. BEGIN IMMEDIATE serializes lookup, mutation and receipt insert.
pub(super) const RECEIPTS: &str = "CREATE TABLE IF NOT EXISTS kernel_mcp_write_receipts (principal_id TEXT NOT NULL, operation TEXT NOT NULL, operation_key TEXT NOT NULL, request_json TEXT NOT NULL, receipt_json TEXT NOT NULL, PRIMARY KEY(principal_id,operation,operation_key))";

// Digest only attachment text; retain every other argument for exact conflicts.
// Accept old receipts on retry, then replace their full text after authorization.
fn request_fingerprint(tool: &str, mut request: Value) -> Result<String> {
    object(&request)?;
    request.as_object_mut().unwrap().remove("idempotency_key");
    if tool == "attach_text" {
        if let Some(text) = request["text"].as_str() {
            use sha2::{Digest, Sha256};
            request["text"] = json!({"sha256":hex::encode(Sha256::digest(text.as_bytes())),"size_bytes":text.len()});
        }
    }
    request.sort_all_objects();
    Ok(serde_json::to_string(&request)?)
}

// Always envelope both user and app requests. An ordinary caller passing an
// app-shaped JSON object as tool arguments must not impersonate stored intent.
fn intent_fingerprint(tool: &str, request: Value, app: Value) -> Result<String> {
    let arguments: Value = serde_json::from_str(&request_fingerprint(tool, request)?)?;
    let mut intent = json!({"schema":"kernel.mcp.intent.v1", "app":app, "arguments":arguments});
    intent.sort_all_objects();
    Ok(serde_json::to_string(&intent)?)
}

// Preserve the stored identity; legacy flat receipts are ordinary-user intent.
fn stored_fingerprint(tool: &str, request: Value) -> Result<String> {
    if request["schema"] == "kernel.mcp.intent.v1" {
        intent_fingerprint(tool, request["arguments"].clone(), request["app"].clone())
    } else {
        intent_fingerprint(tool, request, Value::Null)
    }
}

fn dispatched_fingerprint(tool: &str, request: Value) -> Result<String> {
    intent_fingerprint(
        tool,
        request,
        kernel::app_installs::dispatched_identity().unwrap_or(Value::Null),
    )
}

async fn execute(db: &Db, actor: &str, tool: &str, args: Value) -> Result<Value> {
    if tool == "manage_links" && args["action"] == "list" {
        return list_links(db, actor, args).await;
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
    let request_json = dispatched_fingerprint(tool, args.clone())?;
    let mut tx = begin_write(db.write_pool()).await?;
    // Current consent and source View are checked before success-receipt
    // lookup, on the same serialized snapshot that will perform the effects.
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
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
            let receipt: Value = serde_json::from_str(&receipt)?;
            // Replay does not confer access after revocation or a move.
            let id = if tool == "attach_text" {
                text(&receipt, "attachment_id")?
            } else {
                text(&receipt, "id")?
            };
            if tool == "attach_text" {
                kernel::kernel_require(
                    &mut tx,
                    actor,
                    text(&receipt, "record_id")?,
                    Capability::Edit,
                )
                .await?;
                kernel::blobs::metadata(&mut tx, actor, id).await?;
            }
            if tool == "update_record" && args.get("home_id").is_some() {
                kernel::kernel_require(&mut tx, actor, id, Capability::Manage).await?;
                let home =
                    crate::v1_import::resolve_home_on(&mut tx, actor, text(&args, "home_id")?)
                        .await?;
                kernel::kernel_require(&mut tx, actor, &home, Capability::Edit).await?;
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
                tool == "create_record" && kernel::comments_v2::is_comment_on(&mut tx, id).await?;
            if !creation_is_comment {
                kernel::kernel_require(&mut tx, actor, id, required).await?;
            }
            for target in receipt["link_targets"].as_array().into_iter().flatten() {
                kernel::kernel_require(&mut tx, actor, target.as_str().unwrap(), Capability::View)
                    .await?;
            }
            // Compact legacy receipts only after current-policy authorization.
            sqlx::query("UPDATE kernel_mcp_write_receipts SET request_json=? WHERE principal_id=? AND operation=? AND operation_key=?")
                .bind(&request_json).bind(actor).bind(tool).bind(key).execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(receipt);
        }
    }
    let mut acts = ActAllocation::new();
    use sha2::{Digest, Sha256};
    let pending = kernel::app_installs::start_app_action_in(
        db,
        &mut tx,
        actor,
        tool,
        hex::encode(Sha256::digest(request_json.as_bytes())),
        optional_text(&args, "reason")?.map(str::to_owned),
        &mut acts,
    )
    .await?;
    let mut receipt = match tool {
        "attach_text" => attach_text(db, &mut tx, &mut acts, actor, &args).await?,
        "create_record" => create(db, &mut tx, &mut acts, actor, &args).await?,
        "update_record" => update(db, &mut tx, &mut acts, actor, &args).await?,
        "manage_links" => mutate_link(db, &mut tx, &mut acts, actor, &args).await?,
        "archive_record" => archive(db, &mut tx, &mut acts, actor, &args).await?,
        _ => unreachable!(),
    };
    if let Some(attribution) =
        kernel::app_installs::finish_app_action_in(db, &mut tx, actor, pending, &mut acts).await?
    {
        receipt["app_attribution"] = attribution;
    }
    if let Some(key) = key {
        sqlx::query("INSERT INTO kernel_mcp_write_receipts VALUES(?,?,?,?,?)")
            .bind(actor)
            .bind(tool)
            .bind(key)
            .bind(request_json)
            .bind(serde_json::to_string(&receipt)?)
            .execute(&mut *tx)
            .await?;
    }
    db.commit_kernel_content(tx).await?;
    Ok(receipt)
}

async fn event(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut ActAllocation,
    actor: &str,
    id: &str,
    kind: &str,
    payload: Value,
) -> Result<()> {
    // Callers must authorize before entering a lane: create_input_in checks
    // home Edit; update uses record_edit (Edit + CAS); archive requires Manage.
    // Keep that order when composing lanes. append_in also runs kernel admission.
    append_in(
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
    tx: &mut Transaction<'static, Sqlite>,
    actor: &str,
    id: &str,
) -> Result<kernel::KernelRecordView> {
    // Comment visibility derives through the bearer chain inside the kernel
    // capability check; writes still authorize per lane below.
    kernel::read_record_on(tx, actor, id)
        .await?
        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))
}
// Mint a globally unambiguous UUID prefix, including hidden records and
// imported exact-prefix identities. Saturated scans fall back to the full id.
async fn short_reference(
    tx: &mut Transaction<'static, Sqlite>,
    id: &str,
) -> Result<Option<String>> {
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
            .fetch_all(&mut **tx)
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
    tx: &mut Transaction<'static, Sqlite>,
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
            .fetch_one(&mut **tx)
            .await?;
    let (record_type, kind) = super::v1_type_and_kind(
        current.family.as_deref(),
        current.pin.as_ref().map(|p| p.version),
        primary_type.as_deref(),
        current.kind.as_deref(),
        &current.fields,
    );

    let updated_at: String =
        sqlx::query_scalar("SELECT created_at FROM content_events WHERE seq=?")
            .bind(current.revision)
            .fetch_one(&mut **tx)
            .await?;
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
        .fetch_one(&mut **tx)
        .await?;
        result["act"] = json!(act);
        result["write_receipt"] = json!({"kind":"kernel_content_event","event":{"seq":seq,"event_id":event_id,"event_type":event_type,"record_id":record_id,"created_at":created_at}});
    }
    Ok(result)
}

async fn archive(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
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
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut ActAllocation,
    actor: &str,
    id: &str,
    args: &Value,
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

async fn create(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut ActAllocation,
    actor: &str,
    args: &Value,
) -> Result<Value> {
    create_with_message(db, tx, acts, actor, args, None).await
}
pub(super) async fn create_with_message(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut ActAllocation,
    actor: &str,
    args: &Value,
    message: Option<&kernel::MessageState>,
) -> Result<Value> {
    allowed(
        args,
        &[
            "type",
            "id",
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
            "idempotency_key",
        ],
    )?;
    let typ = text(args, "type")?;
    let raw_kind = text(args, "kind")?;
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
    if message.is_none() && args.get("id").is_some() {
        return Err(invalid("id is only supported for messaging sends"));
    }
    if typ == "Document" && kind == "attachment" {
        return Err(invalid(
            "create_record: use attach_text to create Document/attachment records",
        ));
    }
    validate_lifecycle(args)?;
    let comment = super::comments::is_comment_type(typ, kind);
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
            let requested =
                optional_text(args, "home_id")?.unwrap_or(crate::events::KERNEL_ROOT_ID);
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
    receipt(tx, actor, &id, "created", None, targets).await
}

pub(super) async fn update(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut ActAllocation,
    actor: &str,
    args: &Value,
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
    let previous = view(tx, actor, id).await?;
    // App admission may already own the act. Only events appended by this
    // update count as a data change; allocating attribution is not a save.
    let before_event_seq: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM main.content_events")
            .fetch_one(&mut **tx)
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
        kernel::folder_home_in(db, tx, acts, actor, requested).await?;
        let home = crate::v1_import::resolve_home_on(tx, actor, requested).await?;
        kernel::kernel_require(tx, actor, &home, Capability::Edit).await?;
        // A native home ID must not bypass the liveness/Edit checks on its
        // imported logical folder.
        let logical: Option<String> = sqlx::query_scalar("SELECT json_extract(payload,'$.source_record_id') FROM content_events WHERE record_id=? AND type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(payload,'$.source_record_id') IS NOT NULL ORDER BY seq LIMIT 1")
            .bind(&home).fetch_optional(&mut **tx).await?;
        let destination_id = logical.as_deref().unwrap_or(requested);
        if destination_id != crate::events::KERNEL_ROOT_ID
            && destination_id != crate::schema::ROOT_RECORD_ID
        {
            let native: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id=?)")
                    .bind(destination_id)
                    .fetch_one(&mut **tx)
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
        let updated: String =
            sqlx::query_scalar("SELECT created_at FROM content_events WHERE seq=?")
                .bind(previous.revision)
                .fetch_one(&mut **tx)
                .await?;
        let updated = chrono::DateTime::parse_from_rfc3339(&updated)
            .map_err(|_| invalid("invalid kernel timestamp"))?;
        if updated > expected {
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
                .fetch_one(&mut **tx)
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
            if previous.fields.get(field).unwrap_or(&Value::Null) != value {
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
    if !body_ops.is_empty() {
        let primary_type: Option<String> =
            sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
                .bind(id)
                .fetch_one(&mut **tx)
                .await?;
        let (typ, kind) = super::v1_type_and_kind(
            previous.family.as_deref(),
            previous.pin.as_ref().map(|p| p.version),
            primary_type.as_deref(),
            previous.kind.as_deref(),
            &previous.fields,
        );
        if typ == Some("Document") && kind == Some("artifact") {
            return Err(invalid("artifact body writes require the native source-attestation lane (unsupported_on_v2)"));
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
        let touched = |key: &str| args.get(key).is_some_and(|value| !value.is_null());
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
            touched("lifecycle"),
            optional_text(args, "lifecycle")?,
            touched("summary"),
            optional_text(args, "summary")?,
            next_body.as_deref(),
            touches_part_of,
        )
        .await?;
    }
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
        kernel::revise_input_in(
            db,
            tx,
            acts,
            actor,
            id,
            kernel::FieldInput::Raw(&raw),
            Some(edit_revision),
        )
        .await?;
    }
    metadata_patch(db, tx, acts, actor, id, args).await?;
    if let Some(body) = next_body.filter(|body| body != previous.body.as_deref().unwrap_or("")) {
        event(
            db,
            tx,
            acts,
            actor,
            id,
            "kernel.body_set.v1",
            json!({"body":body}),
        )
        .await?;
    }
    facets(db, tx, acts, actor, id, args.get("facets"), "update_record").await?;
    // Updates never carry a comment bearer link: part_of on a comment is
    // refused by check_update above, so no bearer skips apply here.
    let targets = new_links(db, tx, acts, actor, id, args.get("links"), None).await?;
    let changed: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE seq>?)")
            .bind(before_event_seq)
            .fetch_one(&mut **tx)
            .await?;
    let effect = if changed { "updated" } else { "unchanged" };
    receipt(tx, actor, id, effect, Some(&previous), targets).await
}

fn replace_body(body: &str, args: Value) -> Result<String> {
    let ops: Vec<crate::mcp::tools::lifecycle::BodyReplace> =
        parse("update_record.body_replace", args)?;
    crate::mcp::tools::lifecycle::apply_body_replacements("update_record", body, &ops)
}

type FacetRow = (Option<String>, Option<f64>, Option<String>, String);

async fn facets(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut ActAllocation,
    actor: &str,
    id: &str,
    values: Option<&Value>,
    tool: &str,
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
            Value::String(s) => kernel::FacetObservation {
                key: key.clone(),
                value: Some(s.clone()),
                value_num: None,
                vocab_ref: None,
                as_of: now,
            },
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
        .fetch_optional(&mut **tx)
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
        event(
            db,
            tx,
            acts,
            actor,
            id,
            "kernel.facet_observed.v1",
            serde_json::to_value(observation)?,
        )
        .await?;
    }
    Ok(())
}

async fn new_links(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
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
    tx: &mut Transaction<'static, Sqlite>,
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
async fn change_link(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
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
            .bind(source).bind(target).fetch_one(&mut **tx).await?;
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
    tx: &mut Transaction<'static, Sqlite>,
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

async fn attach_text(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut ActAllocation,
    actor: &str,
    args: &Value,
) -> Result<Value> {
    allowed(
        args,
        &[
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
