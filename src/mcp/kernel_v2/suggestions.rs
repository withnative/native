//! V1 suggestion semantics (tools/suggestions.rs:425,649,725) on one kernel
//! write snapshot. Pure predicates and ordered replacement simulation are shared.
use super::*;
use crate::act::ActAllocation;
use crate::authorization::Capability;
use crate::mcp::tools::suggestions::{self as v1, Precondition, Suggestion};
use sqlx::{Connection, Sqlite, Transaction};
use std::collections::{HashMap, HashSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    action: String,
    suggestion_ids: Vec<String>,
    reason: String,
    #[serde(default)]
    dry_run: bool,
    idempotency_key: Option<String>,
}
const RECEIPTS:&str="CREATE TABLE IF NOT EXISTS kernel_mcp_write_receipts (principal_id TEXT NOT NULL, operation TEXT NOT NULL, operation_key TEXT NOT NULL, request_json TEXT NOT NULL, receipt_json TEXT NOT NULL, PRIMARY KEY(principal_id,operation,operation_key))";
fn error(message: impl AsRef<str>) -> Error {
    Error::engine(format!("resolve_suggestions: {}", message.as_ref()))
}
async fn kind_catalogue(tx: &mut Transaction<'static, Sqlite>) -> Result<sqlx::SqliteConnection> {
    let mut scratch = sqlx::SqliteConnection::connect(":memory:").await?;
    for (name, cols) in [
        ("vocabularies", &["id", "name", "created_at"][..]),
        (
            "vocabulary_values",
            &[
                "id",
                "vocabulary_id",
                "value",
                "gloss",
                "status",
                "ordinal",
                "terminality",
                "metadata",
                "alias_of",
            ][..],
        ),
    ] {
        let rows = kernel::v1_state::rows_on(tx, name).await?;
        let select = cols
            .iter()
            .map(|col| format!("json_extract(value,'$.{col}') AS \"{col}\""))
            .collect::<Vec<_>>()
            .join(",");
        sqlx::query(&format!(
            "CREATE TEMP TABLE {name} AS SELECT {select} FROM json_each(?)"
        ))
        .bind(serde_json::to_string(&rows)?)
        .execute(&mut scratch)
        .await?;
    }
    Ok(scratch)
}
async fn load(
    tx: &mut Transaction<'static, Sqlite>,
    actor: &str,
    ids: &[String],
) -> Result<Vec<Suggestion>> {
    let mut catalogue = kind_catalogue(tx).await?;
    let mut out = Vec::new();
    for id in ids {
        let record = kernel::read_record_on(tx, actor, id)
            .await?
            .ok_or_else(|| error("suggestion does not exist"))?;
        let targets:Vec<String>=sqlx::query_scalar("SELECT target_id FROM kernel_generic_links WHERE source_id=? AND relationship='part_of' AND active=1 ORDER BY target_id").bind(id).fetch_all(&mut **tx).await?;
        if targets.is_empty() {
            return Err(error("suggestion does not exist"));
        }
        for target in &targets {
            // Never echo even a target identifier until its authority is established.
            kernel::kernel_require(tx, actor, target, Capability::Edit)
                .await
                .map_err(|e| match e {
                    Error::Engine(_) => error("suggestion does not exist"),
                    other => other,
                })?;
        }
        let primary: Option<String> =
            sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
                .bind(id)
                .fetch_one(&mut **tx)
                .await?;
        let (typ, kind) = v1_type_and_kind(
            record.family.as_deref(),
            record.pin.as_ref().map(|p| p.version),
            primary.as_deref(),
            record.kind.as_deref(),
            &record.fields,
        );
        let governed = crate::meta::kind::resolve_on(
            &mut catalogue,
            typ.unwrap_or_default(),
            kind.unwrap_or_default(),
        )
        .await?;
        if !crate::generated::kinds::CoreKind::AnnotationSuggestion.matches(&governed) {
            return Err(v1::authoring_error(
                id,
                "expected live Annotation/kind:suggestion",
            ));
        }
        if targets.len() != 1 {
            return Err(v1::authoring_error(
                id,
                format!(
                    "expected exactly one outgoing part_of target; found {}",
                    targets.len()
                ),
            ));
        }
        out.push(Suggestion {
            archived: record.archived,
            id: id.clone(),
            target_id: targets[0].clone(),
            lifecycle: record
                .fields
                .get("lifecycle")
                .and_then(Value::as_str)
                .map(str::to_owned),
            replacement: record.body,
        });
    }
    Ok(out)
}
async fn preconditions(
    tx: &mut Transaction<'static, Sqlite>,
    suggestions: &[Suggestion],
) -> Result<Vec<Precondition>> {
    let mut out = Vec::new();
    for suggestion in suggestions {
        let rows:Vec<(String,Option<String>)>=sqlx::query_as("SELECT key,value FROM kernel_facets WHERE record_id=? AND key IN ('anchor.old','anchor.base_digest','proposal.precondition')").bind(&suggestion.id).fetch_all(&mut **tx).await?;
        let facets: HashMap<String, Option<String>> = rows.into_iter().collect();
        out.push(v1::parse_precondition(suggestion, &facets)?);
    }
    Ok(out)
}
async fn change(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut ActAllocation,
    actor: &str,
    id: &str,
    lifecycle: &str,
    summary: Option<String>,
) -> Result<()> {
    let mut args = json!({"id":id,"lifecycle":lifecycle});
    if let Some(summary) = summary {
        args["summary"] = json!(summary);
    }
    writes::update(db, tx, acts, actor, &args).await?;
    Ok(())
}
fn with_act(mut response: Value, acts: &ActAllocation) -> Value {
    if let Some(act) = acts.get() {
        response["act"] = json!(act);
    }
    response
}

pub(super) async fn resolve(db: &Db, actor: &str, arguments: Value) -> Result<Value> {
    let request = serde_jcs::to_string(&arguments)?;
    let args: Args = parse("resolve_suggestions", arguments)?;
    crate::mcp::tools::require_nonblank_reason("resolve_suggestions", &args.reason)?;
    let ids = &args.suggestion_ids;
    if ids.is_empty() {
        return Err(error("'suggestion_ids' must not be empty"));
    }
    if ids.len() > 100 {
        return Err(error("at most 100 suggestion_ids per call"));
    }
    if ids.iter().collect::<HashSet<_>>().len() != ids.len() {
        return Err(error("'suggestion_ids' must not contain duplicates"));
    }
    let key = crate::mcp::tools::keyed_replay::idempotency_key(
        "resolve_suggestions",
        args.idempotency_key.as_deref(),
    )?;
    match args.action.as_str() {
        "accept" if key.is_some() => {
            return Err(error(
                "accept does not accept idempotency_key yet; retry without a key",
            ))
        }
        "reject" if args.dry_run => return Err(error("dry_run is only valid with action accept")),
        "reject" if ids.len() != 1 => return Err(error("reject takes exactly one suggestion id")),
        "accept" | "reject" => {}
        _ => return Err(error("'action' must be accept or reject")),
    }
    // The lock precedes every predicate and ordered simulation. The kind
    // reader uses only sealed rows captured while this transaction is held.
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    let suggestions = load(&mut tx, actor, ids).await?;
    let target = &suggestions[0].target_id;
    if suggestions.iter().any(|s| &s.target_id != target) {
        return Err(error(
            "all accepted suggestions must share one part_of target",
        ));
    }
    if let Some(key) = key.as_deref() {
        sqlx::query(RECEIPTS).execute(&mut *tx).await?;
        let previous:Option<(String,String)>=sqlx::query_as("SELECT request_json,receipt_json FROM kernel_mcp_write_receipts WHERE principal_id=? AND operation='resolve_suggestions' AND operation_key=?")
            .bind(actor).bind(key).fetch_optional(&mut *tx).await?;
        if let Some((old, receipt)) = previous {
            if old != request {
                return Err(Error::conflict(
                    "idempotency_key reused for different request",
                ));
            }
            let receipt: Value = serde_json::from_str(&receipt)?;
            if let Some(target) = receipt["target_id"].as_str() {
                kernel::kernel_require(&mut tx, actor, target, Capability::Edit).await?;
            }
            return Ok(receipt);
        }
    }
    if let Some(mut response) = v1::lifecycle_conflict(&suggestions, target) {
        if args.dry_run {
            response["status"] = json!("would_conflict");
        }
        return Ok(response);
    }
    let conditions = preconditions(&mut tx, &suggestions).await?;
    if args.action == "accept"
        && suggestions.len() > 1
        && conditions.iter().any(|p| {
            matches!(
                p,
                Precondition::Digest { .. } | Precondition::None { old: None }
            )
        })
    {
        return Err(error(
            "digest and whole-body none suggestions must be accepted alone",
        ));
    }
    let mut acts = ActAllocation::new();
    let record = kernel::read_record_on(&mut tx, actor, target)
        .await?
        .ok_or_else(|| error("suggestion does not exist"))?;
    let mut stale = Vec::new();
    let prospective = if args.action == "accept" {
        stale = v1::stale_causes(&suggestions, &conditions, record.body.as_deref());
        if !stale.is_empty() {
            let stale_ids: Vec<&str> = stale
                .iter()
                .filter_map(|cause| cause["suggestion_id"].as_str())
                .collect();
            let response = json!({"status":if args.dry_run{"would_stale"}else{"stale"},"target_id":target,"suggestion_ids":stale_ids,"causes":stale});
            if args.dry_run {
                return Ok(response);
            }
            None
        } else {
            match v1::simulate(
                &suggestions,
                &conditions,
                record.body.as_deref().unwrap_or_default(),
                target,
                ids,
                args.dry_run,
            ) {
                Ok(body) => {
                    if args.dry_run {
                        return Ok(
                            json!({"status":"would_accept","target_id":target,"suggestion_ids":ids,"prospective_body":body}),
                        );
                    }
                    Some(body)
                }
                Err(conflict) => return Ok(conflict),
            }
        }
    } else {
        None
    };
    let pending = kernel::app_installs::start_app_action_in(
        db,
        &mut tx,
        actor,
        "resolve_suggestions",
        crate::mcp::tools::lifecycle::body_digest(Some(&request)),
        Some(args.reason.clone()),
        &mut acts,
    )
    .await?;
    let response = if !stale.is_empty() {
        for cause in &stale {
            change(
                db,
                &mut tx,
                &mut acts,
                actor,
                cause["suggestion_id"].as_str().unwrap(),
                "stale",
                Some(format!(
                    "Stale: {}",
                    cause["code"].as_str().unwrap_or("precondition_failed")
                )),
            )
            .await?;
        }
        let stale_ids: Vec<&str> = stale
            .iter()
            .filter_map(|cause| cause["suggestion_id"].as_str())
            .collect();
        json!({"status":"stale","target_id":target,"suggestion_ids":stale_ids,"causes":stale})
    } else if let Some(body) = prospective {
        writes::update(db,&mut tx,&mut acts,actor,&json!({"id":target,"body_set":body,"if_body_digest":crate::mcp::tools::lifecycle::body_digest(record.body.as_deref()),"reason":args.reason})).await?;
        for id in ids {
            change(db, &mut tx, &mut acts, actor, id, "accepted", None).await?;
        }
        json!({"status":"accepted","target_id":target,"suggestion_ids":ids})
    } else {
        change(
            db,
            &mut tx,
            &mut acts,
            actor,
            &ids[0],
            "rejected",
            Some(format!("Rejected: {}", args.reason.trim())),
        )
        .await?;
        json!({"status":"rejected","target_id":target,"suggestion_ids":ids})
    };
    let mut response = with_act(response, &acts);
    if let Some(attribution) =
        kernel::app_installs::finish_app_action_in(db, &mut tx, actor, pending, &mut acts).await?
    {
        response["app_attribution"] = attribution;
    }
    if let Some(key) = key.as_deref() {
        sqlx::query("INSERT INTO kernel_mcp_write_receipts VALUES(?,'resolve_suggestions',?,?,?)")
            .bind(actor)
            .bind(key)
            .bind(request)
            .bind(response.to_string())
            .execute(&mut *tx)
            .await?;
    }
    db.commit_kernel_content(tx).await?;
    Ok(response)
}
