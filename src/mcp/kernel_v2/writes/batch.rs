//! Atomic existing-record writes composed from the ordinary v2 leaves.
use super::*;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    reason: String,
    idempotency_key: Option<String>,
    items: Vec<Value>,
    #[serde(default, deserialize_with = "present_sources")]
    sources: Option<Value>,
}

// Preserve explicit null for validation; only omission means undeclared.
fn present_sources<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

struct Item {
    op: String,
    args: Value,
    guard_only: bool,
}
impl Item {
    fn parse(mut raw: Value) -> Result<Self> {
        if raw.get("operation").is_some() || raw.get("arguments").is_some() {
            return Err(invalid("batch items use flat {op, ...} objects, not {operation, arguments}; use op update, add_link or archive"));
        }
        let op = text(&raw, "op")?.to_owned();
        object(&raw)?;
        raw.as_object_mut().unwrap().remove("op");
        let guard_only = match op.as_str() {
            "update" => {
                allowed(
                    &raw,
                    &[
                        "id",
                        "body_set",
                        "body_append",
                        "body_replace",
                        "name",
                        "summary",
                        "maturity",
                        "home_id",
                        "facets",
                        "if_facets",
                        "if_maturity",
                        "if_home_id",
                        "if_body_digest",
                        "if_unmodified_since",
                        "if_policy_revision",
                    ],
                )?;
                for key in [
                    "if_home_id",
                    "if_body_digest",
                    "if_unmodified_since",
                    "if_policy_revision",
                ] {
                    if raw.get(key).is_some() {
                        text(&raw, key)?;
                    }
                }
                if let Some(expected) = raw.get("if_maturity") {
                    if !expected.is_null() && !expected.is_string() {
                        return Err(invalid("if_maturity must be a string or null"));
                    }
                }
                if let Some(expected) = raw.get("if_facets") {
                    if object(expected)?.is_empty() {
                        return Err(invalid("if_facets must not be empty"));
                    }
                }
                let guard_only = ![
                    "body_set",
                    "body_append",
                    "body_replace",
                    "name",
                    "summary",
                    "maturity",
                    "home_id",
                    "facets",
                ]
                .iter()
                .any(|key| {
                    raw.get(*key).is_some_and(|v| {
                        *key != "facets" || v.as_object().is_none_or(|m| !m.is_empty())
                    })
                });
                if guard_only
                    && ![
                        "if_facets",
                        "if_maturity",
                        "if_home_id",
                        "if_body_digest",
                        "if_unmodified_since",
                        "if_policy_revision",
                    ]
                    .iter()
                    .any(|key| raw.get(*key).is_some())
                {
                    return Err(invalid("update names no changes or guards"));
                }
                let update = Self::update_args(&raw, "shape validation");
                validate_update_shape(&update)?;
                guard_only
            }
            "add_link" => {
                allowed(&raw, &["source_id", "target_id", "relationship", "note"])?;
                for key in ["source_id", "target_id", "relationship"] {
                    text(&raw, key)?;
                }
                optional_text(&raw, "note")?;
                false
            }
            "archive" => {
                allowed(&raw, &["id", "archived"])?;
                if raw.get("archived").is_some_and(|v| !v.is_boolean()) {
                    return Err(invalid("archived must be a boolean"));
                }
                false
            }
            _ => {
                return Err(invalid(
                    "use update, add_link or archive items with op at the item level",
                ))
            }
        };
        let item = Self {
            op,
            args: raw,
            guard_only,
        };
        for id in [
            Some(item.id()?),
            item.args.get("target_id").and_then(Value::as_str),
        ]
        .into_iter()
        .flatten()
        {
            if !crate::mcp::record_ref::is_canonical_uuid_v4_or_v7(id) {
                return Err(invalid("batch item requires exact canonical v4/v7 UUIDs"));
            }
        }
        Ok(item)
    }

    fn id(&self) -> Result<&str> {
        text(
            &self.args,
            if self.op == "add_link" {
                "source_id"
            } else {
                "id"
            },
        )
    }

    fn update_args(raw: &Value, reason: &str) -> Value {
        let mut args = raw.clone();
        for key in ["if_facets", "if_maturity", "if_home_id"] {
            args.as_object_mut().unwrap().remove(key);
        }
        args["reason"] = json!(reason);
        args
    }
}

fn item_error(index: usize, error: Error) -> Error {
    let message = format!("batch_write items[{index}]: {error}; nothing written");
    match error {
        Error::Conflict(_) => Error::conflict(message),
        Error::Auth(_) => Error::auth(message),
        _ => invalid(message),
    }
}

async fn check_extra_guards(tx: &mut SqliteConnection, actor: &str, item: &Item) -> Result<()> {
    let id = item.id()?;
    if let Some(expected) = item.args.get("if_home_id") {
        let current = view(tx, actor, id).await?;
        let home = crate::v1_import::resolve_home_on_connection(
            tx,
            actor,
            text(&item.args, "if_home_id")?,
        )
        .await?;
        if current.home_id != home {
            return Err(Error::conflict(format!(
                "home_id no longer matches {expected}"
            )));
        }
    }
    if let Some(expected) = item.args.get("if_maturity") {
        let metadata = kernel::record_metadata::read_on(tx, id).await?;
        if serde_json::to_value(metadata.maturity)? != *expected {
            return Err(Error::conflict(
                "maturity no longer has the expected current value",
            ));
        }
    }
    if let Some(expected) = item.args.get("if_facets") {
        for (key, value) in object(expected)? {
            let parsed = super::super::super::tools::lifecycle::parse_facet_entry(
                "batch_write",
                key,
                value,
                true,
            )?;
            let current: Option<(String, Option<String>)> = sqlx::query_as("SELECT value,vocab_ref FROM kernel_facets WHERE record_id=? AND key=? AND value IS NOT NULL")
                .bind(id).bind(key).fetch_optional(&mut *tx).await?;
            let expected = parsed.map(|facet| (facet.stored_value(), facet.vocab_ref));
            if current != expected {
                return Err(Error::conflict(format!(
                    "facet '{key}' no longer has the expected current value"
                )));
            }
        }
    }
    Ok(())
}

// Guard-only items also apply to sealed Messages, whose content the ordinary
// update leaf correctly refuses. Keep these assertions free of authoring work.
async fn check_common_guards(tx: &mut SqliteConnection, actor: &str, item: &Item) -> Result<()> {
    let id = item.id()?;
    kernel::policy_read::assert_revision_on(
        tx,
        actor,
        id,
        optional_text(&item.args, "if_policy_revision")?,
    )
    .await?;
    if let Some(expected) = optional_text(&item.args, "if_body_digest")? {
        let record = view(tx, actor, id).await?;
        if expected != super::super::super::tools::lifecycle::body_digest(record.body.as_deref()) {
            return Err(Error::conflict("stale if_body_digest"));
        }
    }
    if let Some(expected) = optional_text(&item.args, "if_unmodified_since")? {
        let expected = chrono::DateTime::parse_from_rfc3339(expected)
            .map_err(|_| invalid("if_unmodified_since must be RFC3339"))?;
        let current = kernel::record_metadata::updated_at_on(tx, id).await?;
        let current = chrono::DateTime::parse_from_rfc3339(&current)
            .map_err(|_| invalid("invalid kernel timestamp"))?;
        if current != expected {
            return Err(Error::conflict("stale if_unmodified_since"));
        }
    }
    Ok(())
}

pub(super) async fn execute(db: &Db, actor: &str, caller: &Caller, raw: Value) -> Result<Value> {
    let db = db.clone();
    let actor = actor.to_owned();
    let caller = caller.clone();
    crate::coedit::live::kernel_writes::owned_result(db.clone(), async move {
        execute_owned(&db, &actor, &caller, raw).await
    })
    .await
}

async fn execute_owned(db: &Db, actor: &str, caller: &Caller, raw: Value) -> Result<Value> {
    let args: Args = parse(
        "batch_write: use flat {op, ...} items for update, add_link or archive",
        raw.clone(),
    )?;

    if args.reason.trim().is_empty() {
        return Err(invalid("batch_write requires a nonblank reason"));
    }
    if args.items.is_empty() || args.items.len() > crate::mcp::tools::batch_write::MAX_BATCH_WRITE {
        return Err(invalid("batch_write requires 1..25 items"));
    }
    super::super::source_basis::validate_input(args.sources.as_ref(), "batch_write")?;
    let items = args
        .items
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, raw)| Item::parse(raw).map_err(|error| item_error(index, error)))
        .collect::<Result<Vec<_>>>()?;
    let key = args.idempotency_key.as_deref().map(str::trim);
    if key.is_some_and(|k| k.is_empty() || k.chars().count() > 200) {
        return Err(invalid("idempotency_key must be 1..200 characters"));
    }
    let mut seen = HashMap::new();
    for (index, item) in items.iter().enumerate() {
        if let Some(previous) = seen.insert(item.id()?, index) {
            if index != previous + 1 || !items[previous].guard_only || item.op != "archive" {
                return Err(invalid("batch_write only permits a repeated id for an adjacent guard-only update followed by archive"));
            }
        }
    }
    let fingerprint = dispatched_fingerprint("batch_write", raw)?;
    use crate::coedit::live::kernel_writes::{KernelBodyWrite, KernelTransaction, KernelWriteMode};
    // Holding the writer lane and seed gate prevents new rooms from taking
    // ownership between cohort validation and commit. Existing live/grace
    // rooms refuse without flushing: batch failure has no preflush effects.
    let ownership = KernelBodyWrite::acquire(db, caller, None, KernelWriteMode::Metadata).await?;
    let mut transaction =
        KernelTransaction::begin(db, ownership, KernelBodyWrite::quarantine).await?;
    let result = async {
        let (tx, ownership) = transaction.parts();
        if super::super::principal_on(tx, caller).await? != actor {
            return Err(Error::auth("kernel batch caller binding changed"));
        }
        // Admission and every body/source/receipt path share this serialized
        // writer. Refuse a terminal key before any lookup, guard or effect.
        if let Some(key) = key {
            kernel::mcp_write_receipts::fences::refuse_key_on(tx, actor, "batch_write", key)
                .await?;
        }
        kernel::app_installs::admit_dispatched_on(&mut *tx, actor).await?;
        sqlx::query(RECEIPTS).execute(&mut *tx).await?;
        if let Some(key) = key {
            let old: Option<(String,String)> = sqlx::query_as("SELECT request_json,receipt_json FROM kernel_mcp_write_receipts WHERE principal_id=? AND operation='batch_write' AND operation_key=?")
                .bind(actor).bind(key).fetch_optional(&mut *tx).await?;
            if let Some((request, receipt)) = old {
                if stored_fingerprint("batch_write", serde_json::from_str(&request)?)? != fingerprint {
                    return Err(Error::conflict(
                        "idempotency_key reused for different request",
                    ));
                }
                // V1 batch replay returns a historical receipt after current View
                // on every disclosed target; it must not re-execute old guards.
                for item in &items {
                    kernel::kernel_require(&mut *tx, actor, item.id()?, Capability::View).await?;
                    if let Some(target) = item.args.get("target_id").and_then(Value::as_str) {
                        kernel::kernel_require(&mut *tx, actor, target, Capability::View).await?;
                    }
                    if let Some(home) = item.args.get("home_id").and_then(Value::as_str) {
                        let home =
                            crate::v1_import::resolve_home_on_connection(&mut *tx, actor, home).await?;
                        kernel::kernel_require(&mut *tx, actor, &home, Capability::View).await?;
                    }
                }
                let receipt = serde_json::from_str(&receipt)?;
                return Ok(receipt);
            }
        }
        // Resolve once against the pre-batch snapshot, even when a source is also
        // edited by an earlier item. Every item retains this same revision basis.
        let basis = super::super::source_basis::resolve_on(
            &mut *tx,
            actor,
            args.sources.as_ref(),
            "batch_write",
        )
        .await?;
        let mut acts = ActAllocation::new();
        // Prove the whole cohort before allocating attribution or appending data.
        for (index, item) in items.iter().enumerate() {
            kernel::kernel_require(
                &mut *tx,
                actor,
                item.id()?,
                if item.op == "archive" {
                    Capability::Manage
                } else {
                    Capability::Edit
                },
            )
            .await
            .map_err(|error| item_error(index, error))?;
        }
        for (index, item) in items.iter().enumerate() {
            if ["body_set", "body_append", "body_replace"].iter().any(|key| item.args.get(*key).is_some()) {
                ownership.require_inactive_batch_body(item.id()?).map_err(|error| item_error(index, error))?;
            }
        }
        use sha2::{Digest, Sha256};
        let pending = kernel::app_installs::start_app_action_in(
            db,
            &mut *tx,
            actor,
            "batch_write",
            hex::encode(Sha256::digest(fingerprint.as_bytes())),
            Some(args.reason.clone()),
            &mut acts,
        )
        .await?;
        let mut changed = 0;
        let mut results = Vec::new();
        for (index, item) in items.iter().enumerate() {
            let id = item.id()?;
            let (previous_seq, previous_event_id): (i64, String) = sqlx::query_as(
                "SELECT seq,id FROM main.content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1",
            )
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
            let outcome: Result<Value> = async {
                match item.op.as_str() {
                    "update" => {
                        check_extra_guards(&mut *tx, actor, item).await?;
                        if item.guard_only {
                            check_common_guards(&mut *tx, actor, item).await?;
                            return Ok(json!({"changed":false}));
                        }
                        update_with_context(
                            db,
                            &mut *tx,
                            &mut acts,
                            actor,
                            &Item::update_args(&item.args, &args.reason),
                            None,
                            None,
                            None,
                            false,
                            Some(basis.clone()),
                        )
                        .await
                    }
                    "add_link" => {
                        let mut link = item.args.clone();
                        link["action"] = json!("add");
                        mutate_link(db, &mut *tx, &mut acts, actor, &link).await
                    }
                    "archive" => {
                        let mut archive_args = item.args.clone();
                        archive_args["reason"] = json!(args.reason);
                        archive(db, &mut *tx, &mut acts, actor, &archive_args).await
                    }
                    _ => unreachable!(),
                }
            }
            .await;
            let mut outcome = outcome.map_err(|error| item_error(index, error))?;
            if basis.is_some() && outcome.get("basis").is_none() {
                outcome["basis"] = json!({"status":"not_recorded","source_count":0,
                    "message":"This item produced no field, metadata, body or facet authoring event; shared sources were not retained."});
            }
            let did_change = outcome["changed"] == true;
            changed += usize::from(did_change);
            let mut result = json!({"index":index,"op":item.op,"id":id,"status":if did_change {"changed"} else {"unchanged"},"previous_seq":previous_seq,"previous_event_id":previous_event_id});
            for key in [
                "link",
                "source_id",
                "target_id",
                "relationship",
                "redirected_home",
                "warnings",
                "basis",
                "version",
                "body_digest",
            ] {
                if let Some(value) = outcome.get(key) {
                    result[key] = value.clone();
                }
            }
            results.push(result);
        }
        let mut receipt = json!({"requested":args.items.len(),"changed":changed,"unchanged":args.items.len()-changed,"results":results});
        if let Some(act) = acts.get() {
            receipt["act"] = json!(act);
        }
        if let Some(attribution) =
            kernel::app_installs::finish_app_action_in(db, &mut *tx, actor, pending, &mut acts).await?
        {
            receipt["app_attribution"] = attribution;
        }
        if let Some(key) = key {
            kernel::mcp_write_receipts::record_on(
                db,
                &mut *tx,
                &mut acts,
                kernel::mcp_write_receipts::Outcome {
                    principal: actor,
                    operation: "batch_write",
                    key,
                    request: &fingerprint,
                    receipt: &serde_json::to_string(&receipt)?,
                },
            )
            .await?;
        }
        Ok::<_, Error>(receipt)
    }.await;
    let receipt = match result {
        Ok(receipt) => receipt,
        Err(error) => return Err(transaction.rollback(error).await),
    };
    transaction.commit().await?;
    Ok(receipt)
}
