//! Authenticated host operations; no client-supplied account or workspace scope.
use super::*;
use crate::kernel::saved_tabs::{self as saved, Change, Definition, Location, Row};
use crate::store::{append_in, AppendSpec};
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Args {
    Create {
        creation_key: String,
        app: String,
        initial_record_id: Option<String>,
        reason: String,
    },
    Get {
        record_id: String,
    },
    List {
        #[serde(default = "default_limit")]
        limit: u32,
        after: Option<String>,
        #[serde(default)]
        include_retired: bool,
    },
    Rename {
        record_id: String,
        expected_revision: String,
        operation_id: String,
        custom_title: Option<String>,
        reason: String,
    },
    Retire {
        record_id: String,
        expected_revision: String,
        operation_id: String,
        reason: String,
    },
}
fn default_limit() -> u32 {
    50
}
fn receipt(outcome: &str, row: &Row) -> Result<Value> {
    Ok(json!({"outcome":outcome,"tab":row.value()?,"changed":false}))
}

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_engine_handler(
        "manage_saved_tabs",
        EngineKind::KernelV2,
        |engine, caller, args| async move {
            let EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            execute(&db, &caller, args).await
        },
    )
}
async fn execute(db: &Db, caller: &Caller, arguments: Value) -> Result<Value> {
    if !crate::identity::account::is_account_token(caller.credential())
        || caller.host_asserted_app().is_some()
    {
        return Err(Error::engine(
            "manage_saved_tabs: authenticated host account required",
        ));
    }
    // Bound the complete admitted request, including reason and identifiers.
    if serde_json::to_vec(&arguments)?.len() > 2048 {
        return Err(Error::engine("manage_saved_tabs: request exceeds 2 KiB"));
    }
    // Null is explicit for reset and initial destination. Omission is a malformed request.
    if (arguments["action"] == "rename" && arguments.get("custom_title").is_none())
        || (arguments["action"] == "create" && arguments.get("initial_record_id").is_none())
    {
        return Err(Error::engine(
            "manage_saved_tabs: explicit nullable field required",
        ));
    }
    let args: Args = parse("manage_saved_tabs", arguments.clone())?;
    let actor = principal(db, caller).await?;
    let read_only = matches!(args, Args::List { .. } | Args::Get { .. });
    let mut tx = if read_only {
        db.pool().begin().await?
    } else {
        crate::db::begin_write(db.write_pool()).await?
    };
    let account = identity_read::principal_account_on(&mut tx, &actor).await?;
    if account.as_deref() != Some(caller.credential()) {
        return Err(Error::engine(
            "manage_saved_tabs: canonical account required",
        ));
    }
    if !saved::available_on(&mut tx).await? {
        tx.rollback().await?;
        return Ok(
            json!({"outcome":"unavailable","requirement":"saved_tabs_not_prepared","engine":"kernel_v2"}),
        );
    }
    // Existing databases must run explicit v2 preparation, never serving-time DDL.
    match args {
        Args::List {
            limit,
            after,
            include_retired,
        } => {
            if !(1..=100).contains(&limit) {
                return Err(Error::engine("manage_saved_tabs: limit must be 1..100"));
            }
            if let Some(cursor) = &after {
                saved::token(cursor, 256)?;
            }
            let sql = if include_retired {
                "SELECT s.record_id,s.creation_key,s.create_digest,s.definition,e.id AS event_id FROM main.kernel_saved_tabs s JOIN main.content_events e ON e.seq=s.event_seq WHERE s.principal_id=? AND s.record_id>? ORDER BY s.record_id LIMIT ?"
            } else {
                "SELECT s.record_id,s.creation_key,s.create_digest,s.definition,e.id AS event_id FROM main.kernel_saved_tabs s JOIN main.content_events e ON e.seq=s.event_seq WHERE s.principal_id=? AND json_extract(s.definition,'$.state')='active' AND s.record_id>? ORDER BY s.record_id LIMIT ?"
            };
            let rows: Vec<Row> = sqlx::query_as(sql)
                .bind(&actor)
                .bind(after.unwrap_or_default())
                .bind(limit + 1)
                .fetch_all(&mut *tx)
                .await?;
            let more = rows.len() > limit as usize;
            let tabs = rows
                .iter()
                .take(limit as usize)
                .map(Row::value)
                .collect::<Result<Vec<_>>>()?;
            let cursor = if more {
                tabs.last()
                    .and_then(|t| t["record_id"].as_str())
                    .map(str::to_owned)
            } else {
                None
            };
            tx.rollback().await?;
            Ok(json!({"tabs":tabs,"next_cursor":cursor}))
        }
        Args::Get { record_id } => {
            let row = saved::read_on(&mut tx, &actor, &record_id)
                .await?
                .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
            tx.rollback().await?;
            receipt("existing", &row)
        }
        Args::Create {
            creation_key,
            app,
            initial_record_id,
            reason,
        } => {
            saved::token(&creation_key, 256)?;
            saved::token(&app, 256)?;
            if let Some(id) = &initial_record_id {
                saved::token(id, 256)?;
            }
            if reason.trim().is_empty() {
                return Err(Error::engine("manage_saved_tabs: reason must be nonblank"));
            }
            // A retry's explanatory reason is immaterial to working-slot identity.
            let digest = hex::encode(Sha256::digest(serde_json::to_vec(
                &json!({"app":app,"initial_record_id":initial_record_id}),
            )?));
            let old: Option<Row> = sqlx::query_as("SELECT s.record_id,s.creation_key,s.create_digest,s.definition,e.id AS event_id FROM main.kernel_saved_tabs s JOIN main.content_events e ON e.seq=s.event_seq WHERE s.principal_id=? AND s.creation_key=?")
                .bind(&actor).bind(&creation_key).fetch_optional(&mut *tx).await?;
            if let Some(old) = old {
                if old.create_digest != digest {
                    return Err(Error::conflict(
                        "saved tab creation key reused for different initial identity",
                    ));
                }
                tx.rollback().await?;
                return receipt(
                    if old.definition()?.state == "retired" {
                        "retired"
                    } else {
                        "existing"
                    },
                    &old,
                );
            }
            let definition = Definition {
                version: 1,
                app,
                custom_title: None,
                initial_location: Location {
                    record_id: initial_record_id,
                },
                state: "active".into(),
            };
            let mut acts = crate::act::ActAllocation::new();
            let raw = serde_json::to_string(&definition.fields())?;
            let id = kernel::create_input_admitted_in(
                db,
                &mut tx,
                &mut acts,
                &actor,
                crate::v2_standard::saved_tabs::FAMILY,
                "saved_tab",
                kernel::FieldInput::Raw(&raw),
                crate::events::KERNEL_ROOT_ID,
                None,
                false,
                None,
                Some(json!({"saved_tab_creation_key":creation_key})),
                None,
            )
            .await?;
            kernel::account_only_record_in(db, &mut tx, &mut acts, &actor, &id).await?;
            append_in(
                db,
                &mut tx,
                AppendSpec {
                    record_id: id.clone(),
                    event_type: saved::EVENT.into(),
                    actor: Some(actor.clone()),
                    payload: serde_json::to_value(Change {
                        created_act: acts.get(),
                        principal_id: actor.clone(),
                        creation_key,
                        operation_id: None,
                        expected_revision: None,
                        definition,
                        request_digest: digest,
                        reason,
                    })?,
                },
                &mut acts,
            )
            .await?;
            let row = saved::read_on(&mut tx, &actor, &id)
                .await?
                .ok_or_else(|| Error::engine("saved tab creation failed"))?;
            db.commit_kernel_content(tx).await?;
            let mut result = receipt("created", &row)?;
            result["changed"] = json!(true);
            Ok(result)
        }
        Args::Rename {
            record_id,
            expected_revision,
            operation_id,
            custom_title,
            reason,
        } => {
            let desired = custom_title
                .as_deref()
                .map(saved::normalize_title)
                .transpose()?;
            mutate(
                db,
                tx,
                &actor,
                &record_id,
                &expected_revision,
                &operation_id,
                Some(desired),
                &reason,
            )
            .await
        }
        Args::Retire {
            record_id,
            expected_revision,
            operation_id,
            reason,
        } => {
            mutate(
                db,
                tx,
                &actor,
                &record_id,
                &expected_revision,
                &operation_id,
                None,
                &reason,
            )
            .await
        }
    }
}
#[allow(clippy::too_many_arguments)]
async fn mutate(
    db: &Db,
    mut tx: sqlx::Transaction<'static, sqlx::Sqlite>,
    actor: &str,
    id: &str,
    expected: &str,
    operation: &str,
    title: Option<Option<String>>,
    reason: &str,
) -> Result<Value> {
    saved::token(operation, 256)?;
    if reason.trim().is_empty() || expected.is_empty() {
        return Err(Error::engine(
            "saved tab mutation requires reason and expected revision",
        ));
    }
    let old = saved::read_on(&mut tx, actor, id)
        .await?
        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    let digest = hex::encode(Sha256::digest(serde_json::to_vec(
        &json!({"record_id":id,"expected_revision":expected,"title":title,"retire":title.is_none()}),
    )?));
    let prior: Option<(String,String)> = sqlx::query_as("SELECT record_id,request_digest FROM main.kernel_saved_tab_operations WHERE principal_id=? AND operation_id=?")
        .bind(actor).bind(operation).fetch_optional(&mut *tx).await?;
    if let Some((prior_id, prior_digest)) = prior {
        if prior_id != id || prior_digest != digest {
            return Err(Error::conflict(
                "saved tab operation id reused with different arguments",
            ));
        }
        tx.rollback().await?;
        return receipt("replayed", &old);
    }
    let mut definition = old.definition()?;
    if definition.state == "retired" {
        tx.rollback().await?;
        return receipt("retired", &old);
    }
    let converged = title
        .as_ref()
        .is_some_and(|title| title == &definition.custom_title);
    if old.revision() != expected && !converged {
        tx.rollback().await?;
        return receipt("conflict", &old);
    }
    let retire = title.is_none();
    if let Some(title) = title {
        definition.custom_title = title;
    } else {
        definition.state = "retired".into();
    }
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: id.into(),
            event_type: saved::EVENT.into(),
            actor: Some(actor.into()),
            payload: serde_json::to_value(Change {
                created_act: None,
                principal_id: actor.into(),
                creation_key: old.creation_key.clone(),
                operation_id: Some(operation.into()),
                expected_revision: Some(old.revision()),
                definition,
                request_digest: digest,
                reason: reason.into(),
            })?,
        },
        &mut acts,
    )
    .await?;
    let row = saved::read_on(&mut tx, actor, id)
        .await?
        .ok_or_else(|| Error::engine("saved tab update failed"))?;
    db.commit_kernel_content(tx).await?;
    let mut result = receipt(
        if retire {
            "retired"
        } else if converged {
            "converged"
        } else {
            "updated"
        },
        &row,
    )?;
    result["changed"] = json!(true);
    Ok(result)
}
