//! Reads of an activated native canvas. Imported public positions and payloads
//! stay continuous with the saved Whiteboard client's replication cursor.
mod promotion;

use super::*;
use crate::canvas::{self, CanvasVersion, SceneObject, StoredBatch};
use crate::mcp::tools::canvas as disclosure;
use sqlx::{Row, SqliteConnection};
use std::collections::{BTreeSet, HashMap, HashSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum Args {
    GetScene {
        canvas_id: String,
        #[serde(default)]
        include_deleted: bool,
    },
    Changes {
        canvas_id: String,
        after: String,
        limit: Option<usize>,
    },
    Describe {
        canvas_id: String,
    },
}

pub(super) async fn read(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let args: Args = parse("read_canvas", args)?;
    let (id, after, limit) = match &args {
        Args::GetScene { canvas_id, .. } | Args::Describe { canvas_id } => (canvas_id, None, 0),
        Args::Changes {
            canvas_id,
            after,
            limit,
        } => {
            let after = CanvasVersion::parse(after)
                .ok_or_else(|| Error::engine("read_canvas: after must be a canvas:N token"))?;
            let limit = limit.unwrap_or(200);
            if !(1..=1000).contains(&limit) {
                return Err(Error::engine("read_canvas: limit must be 1-1000"));
            }
            (canvas_id, Some(after), limit)
        }
    };
    let mut tx = db.write_pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    kernel::kernel_require(&mut tx, actor, id, crate::authorization::Capability::View).await?;
    if kernel::canvas_v2::ready_on(&mut tx, id, i64::MAX)
        .await?
        .is_none()
    {
        return Err(Error::engine("read_canvas: canvas is not activated on v2"));
    }
    let head = canvas::current_version(&mut tx, id).await?;
    let output = if let Some(after) = after {
        changes(&mut tx, actor, id, after, head, limit).await?
    } else {
        let include_deleted = matches!(
            args,
            Args::GetScene {
                include_deleted: true,
                ..
            }
        );
        let objects = canvas::load_scene(&mut tx, id, include_deleted).await?;
        let live = objects.iter().filter(|object| !object.deleted).count();
        let mut values: Vec<Value> = objects.iter().map(SceneObject::to_value).collect();
        let refs = disclosure::referenced_record_ids(&values, &[]);
        let (visible, faces) = references(&mut tx, actor, &refs).await?;
        let cards: HashMap<String, String> = objects
            .iter()
            .filter_map(|object| {
                (object.kind == canvas::ObjectKind::RecordCard)
                    .then(|| {
                        object
                            .props
                            .get("record_id")
                            .and_then(Value::as_str)
                            .map(|id| (object.id.clone(), id.to_owned()))
                    })
                    .flatten()
            })
            .collect();
        for value in &mut values {
            disclosure::redact_object(value, &visible, &faces);
        }
        connectors(&mut tx, &mut values, &cards, &visible).await?;
        if matches!(args, Args::Describe { .. }) {
            canvas::describe_scene(id, head, &values)
        } else {
            json!({"action":"get_scene","version":canvas::SCENE_VERSION,
                "canvas_id":id,"canvas_version":head.encode(),"resolved_content_seq":null,
                "include_deleted":include_deleted,"objects":values,"live_objects":live,
                "limits":{"ops_per_batch":canvas::MAX_OPS_PER_BATCH,
                    "batch_bytes":canvas::MAX_BATCH_CANONICAL_BYTES,"live_objects":canvas::MAX_LIVE_OBJECTS}})
        }
    };
    tx.rollback().await?;
    Ok(output)
}

async fn references(
    conn: &mut SqliteConnection,
    actor: &str,
    ids: &[String],
) -> Result<(HashSet<String>, HashMap<String, Value>)> {
    let mut visible = HashSet::new();
    let mut faces = HashMap::new();
    for id in ids {
        let Some(record) = kernel::read_record_on(conn, actor, id).await? else {
            continue;
        };
        let primary_type: Option<String> =
            sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
                .bind(id)
                .fetch_one(&mut *conn)
                .await?;
        let (typ, kind) = v1_type_and_kind(
            record.family.as_deref(),
            record.pin.as_ref().map(|p| p.version),
            primary_type.as_deref(),
            record.kind.as_deref(),
            &record.fields,
        );
        let field = |name: &str| record.fields.get(name).cloned().unwrap_or(Value::Null);
        faces.insert(
            id.clone(),
            json!({"id":id,"type":typ,"kind":kind,
            "name":record.fields.get("title").cloned().unwrap_or_else(||field("name")),
            "summary":field("summary"),"maturity":field("maturity"),
            "archived":record.archived,"version":format!("rec:{}",record.revision)}),
        );
        visible.insert(id.clone());
    }
    Ok((visible, faces))
}

async fn connectors(
    conn: &mut SqliteConnection,
    values: &mut [Value],
    cards: &HashMap<String, String>,
    visible: &HashSet<String>,
) -> Result<()> {
    for object in values {
        if object["kind"] != "connector" || !object["props"]["semantic"].is_object() {
            continue;
        }
        let source = object
            .pointer("/props/from/object")
            .and_then(Value::as_str)
            .and_then(|id| cards.get(id));
        let target = object
            .pointer("/props/to/object")
            .and_then(Value::as_str)
            .and_then(|id| cards.get(id));
        let (Some(source), Some(target)) = (source, target) else {
            object["props"]["semantic"] = json!(canvas::WITHHELD);
            continue;
        };
        if !visible.contains(source) || !visible.contains(target) {
            object["props"]["semantic"] = json!(canvas::WITHHELD);
            continue;
        }
        if object["props"]["semantic"]["status"] == "asserted" {
            let relationship = object["props"]["semantic"]["relationship"]
                .as_str()
                .unwrap_or_default();
            let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_generic_links WHERE source_id=? AND target_id=? AND relationship=? AND active=1)")
                .bind(source).bind(target).bind(relationship).fetch_one(&mut *conn).await?;
            if !live {
                object["props"]["semantic"]["status"] = json!("broken");
            }
        }
    }
    Ok(())
}

async fn changes(
    conn: &mut SqliteConnection,
    actor: &str,
    id: &str,
    after: CanvasVersion,
    head: CanvasVersion,
    limit: usize,
) -> Result<Value> {
    // Source rows are private evidence; never expose the W5 wrapping event as
    // another logical batch. Each batch is ordered by its public position.
    let rows = sqlx::query(
        "SELECT b.batch_id,b.actor,b.event_id,b.event_seq,
        coalesce(s.payload,e.payload) AS payload,coalesce(s.created_at,e.created_at) AS created_at
        FROM canvas_batches b LEFT JOIN kernel_canvas_source_events s ON s.event_id=b.event_id
        LEFT JOIN content_events e ON e.id=b.event_id
        WHERE b.canvas_id=? AND b.event_seq>? ORDER BY b.event_seq LIMIT ?",
    )
    .bind(id)
    .bind(after.0)
    .bind(limit as i64 + 1)
    .fetch_all(&mut *conn)
    .await?;
    let more = rows.len() > limit;
    let stored = rows
        .iter()
        .take(limit)
        .map(|row| {
            let payload: String = row.try_get("payload")?;
            serde_json::from_str::<StoredBatch>(&payload).map_err(Error::from)
        })
        .collect::<Result<Vec<_>>>()?;
    let refs = stored
        .iter()
        .flat_map(|batch| disclosure::referenced_record_ids(&[], &batch.ops))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let (visible, _) = references(conn, actor, &refs).await?;
    let allowed = kernel::v1_state::disclosed_accounts_on(conn, actor).await?;
    let mut batches = Vec::new();
    for (row, stored) in rows.iter().zip(stored) {
        let author: Option<String> = row.try_get("actor")?;
        let author = if let Some(author) = author.filter(|id| allowed.contains(id)) {
            let label: Option<String> = sqlx::query_scalar(
                "SELECT display_label FROM kernel_principals WHERE principal_id=?",
            )
            .bind(&author)
            .fetch_optional(&mut *conn)
            .await?
            .flatten();
            json!({"id":author,"display_name":label})
        } else {
            Value::Null
        };
        let seq: i64 = row.try_get("event_seq")?;
        batches.push(json!({"batch_id":row.try_get::<String,_>("batch_id")?,
            "event_id":row.try_get::<String,_>("event_id")?,"event_seq":seq,
            "canvas_version":CanvasVersion(seq).encode(),"actor":author,
            "at":row.try_get::<String,_>("created_at")?,"origin":stored.origin,
            "base_version":stored.base_version,"detached":stored.detached,
            "ops":stored.ops.iter().map(|op|disclosure::redact_op(op,&visible)).collect::<Vec<_>>(),
            "pre_images":disclosure::redact_pre_images(&stored.pre_images,&visible)}));
    }
    let next = batches
        .last()
        .map(|b| b["canvas_version"].clone())
        .unwrap_or_else(|| json!(after.encode()));
    Ok(
        json!({"action":"changes","version":canvas::CHANGES_VERSION,"canvas_id":id,
        "after":after.encode(),"canvas_version":head.encode(),"batches":batches,
        "more":more,"next_after":next}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ManageArgs {
    CommitBatch { batch: Value },
}

pub(super) async fn manage(db: &Db, actor: &str, args: Value) -> Result<Value> {
    use crate::canvas::{BatchEnvelope, FoldError};
    use crate::kernel::canvas_v2::{self as native, PreparedBatch};
    if args["action"] == "promote" {
        return promotion::execute(db, actor, args).await;
    }
    let ManageArgs::CommitBatch { batch } = parse("manage_canvas", args.clone())?;
    let id = batch["batch_id"].as_str();
    let envelope: BatchEnvelope = match serde_json::from_value(batch.clone()) {
        Ok(envelope) => envelope,
        Err(error) => {
            return Ok(disclosure::rejected(
                id,
                None,
                &disclosure::refusal("invalid_envelope", format!("batch does not parse: {error}")),
            ))
        }
    };
    if let Err(error) = canvas::validate_envelope(&envelope) {
        return match error {
            FoldError::Refused(refusal) => Ok(disclosure::rejected(id, None, &refusal)),
            FoldError::Engine(error) => Err(error),
        };
    }
    let id = Some(envelope.batch_id.as_str());
    let canvas_id = &envelope.canvas_id;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    let capability = kernel::kernel_effective_capability_on(&mut tx, actor, canvas_id).await?;
    if !capability.allows(crate::authorization::Capability::View) {
        return Ok(disclosure::rejected(
            id,
            None,
            &disclosure::refusal("unknown_canvas", "canvas does not exist"),
        ));
    }
    if !native::is_canvas_shell(&mut tx, canvas_id).await? {
        return Ok(disclosure::rejected(
            id,
            None,
            &disclosure::refusal("unknown_canvas", "canvas does not exist"),
        ));
    }
    let Some(floor) = native::ready_on(&mut tx, canvas_id, i64::MAX).await? else {
        return Ok(disclosure::rejected(
            id,
            None,
            &disclosure::refusal("unsupported_on_v2", "canvas has not been activated"),
        ));
    };
    if !capability.allows(crate::authorization::Capability::Edit) {
        return Ok(disclosure::rejected(
            id,
            None,
            &disclosure::refusal("permission_denied", "canvas requires edit capability"),
        ));
    }
    let head = canvas::current_version(&mut tx, canvas_id).await?;
    let refs = disclosure::referenced_record_ids(&[], &envelope.ops);
    let (visible, _) = references(&mut tx, actor, &refs).await?;
    if let Some(hidden) = refs.iter().find(|id| !visible.contains(*id)) {
        return Ok(disclosure::rejected(
            id,
            Some(head),
            &disclosure::refusal(
                "record_not_visible",
                format!("record {hidden} does not exist"),
            ),
        ));
    }
    let digest = canvas::ops_digest(&envelope.ops)?;
    let old = sqlx::query(
        "SELECT b.actor,b.event_id,b.event_seq,b.ops_sha256,
        coalesce(s.payload,e.payload) AS payload,e.act,s.event_id IS NOT NULL AS imported
        FROM canvas_batches b LEFT JOIN kernel_canvas_source_events s ON s.event_id=b.event_id
        LEFT JOIN content_events e ON e.id=b.event_id
        WHERE b.canvas_id=? AND b.batch_id=?",
    )
    .bind(canvas_id)
    .bind(&envelope.batch_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(old) = old {
        if old.try_get::<Option<String>, _>("actor")?.as_deref() != Some(actor)
            || old.try_get::<String, _>("ops_sha256")? != digest
        {
            return Ok(disclosure::rejected(id,Some(head),&disclosure::refusal("batch_id_reused",
                "this batch_id was already committed with different ops or by a different actor")));
        }
        let event_id: String = old.try_get("event_id")?;
        let position: i64 = old.try_get("event_seq")?;
        let stored: StoredBatch = serde_json::from_str(&old.try_get::<String, _>("payload")?)?;
        let attribution = original_attribution(&mut tx, actor, &event_id).await?;
        // Native receipt authority is scoped to its original app generation.
        // Do not disclose another app's private attribution through a guessed
        // batch ID. V1 source retries have no native attribution witness and
        // keep their actor+ops semantics without claiming a new app action.
        if !old.try_get::<bool, _>("imported")? {
            if let Some(current) = kernel::app_installs::dispatched_identity() {
                let same = attribution.as_ref().is_some_and(|original| {
                    ["package", "version", "install_event_id"]
                        .iter()
                        .all(|key| original[*key] == current[*key])
                });
                if !same {
                    return Ok(disclosure::rejected(
                        id,
                        Some(head),
                        &disclosure::refusal(
                            "batch_id_reused",
                            "this batch_id belongs to a different accepted action",
                        ),
                    ));
                }
            }
        }
        let mut result = batch_result(
            "replayed",
            &event_id,
            position,
            &stored,
            old.try_get("act")?,
        );
        if let Some(attribution) = attribution {
            result["app_attribution"] = attribution;
        }
        tx.rollback().await?;
        return Ok(result);
    }
    let next: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0)+1 FROM main.content_events")
        .fetch_one(&mut *tx)
        .await?;
    let position = native::public_position(floor, next)?;
    let prepared = native::prepare_batch(&mut tx, &envelope, position).await;
    let stored = match prepared {
        Ok(PreparedBatch::Ready(stored)) => stored,
        Ok(PreparedBatch::Conflicts(conflicts)) => {
            let mut items = Vec::new();
            let allowed = kernel::v1_state::disclosed_accounts_on(&mut tx, actor).await?;
            for conflict in conflicts {
                let author: Option<String> = if let Some(seq) = conflict.competing_seq {
                    sqlx::query_scalar(
                        "SELECT actor FROM canvas_batches WHERE canvas_id=? AND event_seq=?",
                    )
                    .bind(canvas_id)
                    .bind(seq)
                    .fetch_optional(&mut *tx)
                    .await?
                    .flatten()
                } else {
                    None
                };
                let author = if let Some(author) = author.filter(|id| allowed.contains(id)) {
                    let label: Option<String> = sqlx::query_scalar(
                        "SELECT display_label FROM kernel_principals WHERE principal_id=?",
                    )
                    .bind(&author)
                    .fetch_optional(&mut *tx)
                    .await?;
                    json!({"id":author,"display_name":label})
                } else {
                    Value::Null
                };
                let mut item =
                    json!({"id":conflict.id,"code":conflict.code,"competing_actor":author});
                if let Some(group) = conflict.group {
                    item["group"] = json!(group);
                }
                if let Some(current) = conflict.current {
                    item["current"] = current;
                }
                items.push(item);
            }
            return Ok(
                json!({"action":"commit_batch","version":canvas::RESULT_VERSION,
                "outcome":"conflict","batch_id":envelope.batch_id,"canvas_version":head.encode(),
                "base_version":envelope.base_version,"objects":{},"conflicts":items,
                "error":{"code":"precondition_failed","message":"one or more preconditions no longer hold; nothing was written"}}),
            );
        }
        Err(FoldError::Refused(refusal)) => {
            return Ok(disclosure::rejected(id, Some(head), &refusal))
        }
        Err(FoldError::Engine(error)) => return Err(error),
    };
    let mut acts = crate::act::ActAllocation::new();
    let request_digest = crate::canonical_json::digest_json(
        &json!({"app":kernel::app_installs::dispatched_identity(),"arguments":args}),
    );
    let pending = kernel::app_installs::start_app_action_in(
        db,
        &mut tx,
        actor,
        "manage_canvas",
        request_digest,
        envelope.origin.note.clone(),
        &mut acts,
    )
    .await?;
    let event = crate::store::append_in(
        db,
        &mut tx,
        crate::store::AppendSpec {
            record_id: canvas_id.clone(),
            event_type: native::BATCH.into(),
            payload: serde_json::to_value(&stored)?,
            actor: Some(actor.into()),
        },
        &mut acts,
    )
    .await?;
    let position = native::public_position(floor, event.local_seq)?;
    let mut result = batch_result("committed", &event.id, position, &stored, event.act);
    result["write_receipt"] = json!({"kind":"content_event","event":{
        "seq":event.local_seq,"event_id":event.id,"record_id":canvas_id,
        "event_type":event.event_type,"created_at":event.created_at}});
    if let Some(attribution) =
        kernel::app_installs::finish_app_action_in(db, &mut tx, actor, pending, &mut acts).await?
    {
        result["app_attribution"] = attribution;
    }
    db.commit_kernel_content(tx).await?;
    Ok(result)
}

fn batch_result(
    outcome: &str,
    event_id: &str,
    position: i64,
    stored: &StoredBatch,
    act: Option<i64>,
) -> Value {
    let mut result = json!({"action":"commit_batch","version":canvas::RESULT_VERSION,
        "outcome":outcome,"batch_id":stored.batch_id,"canvas_version":CanvasVersion(position).encode(),
        "event_id":event_id,"objects":canvas::versions_after(position,&stored.ops,&stored.pre_images,&stored.detached),
        "conflicts":[]});
    if let Some(act) = act {
        result["act"] = json!(act);
    }
    result
}

async fn original_attribution(
    conn: &mut SqliteConnection,
    actor: &str,
    event_id: &str,
) -> Result<Option<Value>> {
    let row = sqlx::query("SELECT a.event_id,a.admitted_event_id,a.package,a.version,a.install_generation
        FROM kernel_app_actions a WHERE a.principal=? AND a.operation='manage_canvas'
        AND EXISTS(SELECT 1 FROM json_each(a.outputs_json) o WHERE json_extract(o.value,'$.event_id')=?)
        ORDER BY a.event_seq LIMIT 1").bind(actor).bind(event_id).fetch_optional(conn).await?;
    row.map(|row| Ok(json!({"schema":"native.app-action.v1","event_id":row.try_get::<String,_>("event_id")?,
        "admitted_event_id":row.try_get::<String,_>("admitted_event_id")?,"package":row.try_get::<String,_>("package")?,
        "version":row.try_get::<String,_>("version")?,"install_event_id":row.try_get::<String,_>("install_generation")?}))).transpose()
}
