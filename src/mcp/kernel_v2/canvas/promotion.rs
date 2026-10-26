//! Native composite canvas promotion. Plans retain the v1 digest and wire shape.
use super::super::writes;
use crate::mcp::tools::canvas::{
    self as legacy, frame_has_children, promotion_digest, version_moved, PromoteExpected,
    PromoteItem, PromoteLink, MAX_PROMOTE_ITEMS,
};
use crate::{
    authorization::Capability,
    canvas::{self, *},
    db::{begin_write, Db},
    kernel, Error, Result,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sqlx::{Sqlite, Transaction};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    action: String,
    canvas_id: String,
    items: Vec<PromoteItem>,
    #[serde(default)]
    links: Vec<PromoteLink>,
    #[serde(default)]
    dry_run: bool,
    expected: Option<PromoteExpected>,
    plan_digest: Option<String>,
    reason: String,
}
async fn can_record_in(
    tx: &mut Transaction<'static, Sqlite>,
    actor: &str,
    id: &str,
    capability: Capability,
) -> Result<bool> {
    Ok(kernel::kernel_effective_capability_on(tx, actor, id)
        .await?
        .allows(capability)
        && !kernel::hq::tombstoned_on(tx, id).await?)
}
fn is_reserved_relationship(name: &str) -> bool {
    crate::surface_binding::is_reserved_relationship(name)
}
fn refusal(code: &'static str, message: impl Into<String>) -> Refusal {
    legacy::refusal(code, message)
}

pub(super) async fn execute(db: &Db, actor: &str, arguments: Value) -> Result<Value> {
    let Args {
        action,
        canvas_id,
        items,
        links,
        dry_run,
        expected,
        plan_digest,
        reason,
    } = serde_json::from_value(arguments.clone())?;
    if action != "promote" {
        return Err(Error::engine("invalid promotion action"));
    }
    let deny = |refusal: &Refusal| {
        let mut value = legacy::refused("promote", None, None, refusal);
        value["version"] = json!(PROMOTE_VERSION);
        value
    };
    if reason.trim().is_empty() {
        return Ok(deny(&refusal(
            "invalid_envelope",
            "promote requires a reason",
        )));
    }
    if items.is_empty() || items.len() > MAX_PROMOTE_ITEMS {
        return Ok(deny(&refusal(
            "limit_exceeded",
            "promote requires 1-50 items",
        )));
    }
    let mut seen = BTreeSet::new();
    if items.iter().any(|item| !seen.insert(&item.object_id)) {
        return Ok(deny(&refusal(
            "duplicate_object",
            "an object may be promoted once per plan",
        )));
    }
    let mut tx = begin_write(db.write_pool()).await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    if !can_record_in(&mut tx, actor, &canvas_id, Capability::View).await?
        || !kernel::canvas_v2::is_canvas_shell(&mut tx, &canvas_id).await?
    {
        return Ok(deny(&refusal("unknown_canvas", "canvas does not exist")));
    }
    let floor = kernel::canvas_v2::ready_on(&mut tx, &canvas_id, i64::MAX)
        .await?
        .ok_or_else(|| Error::engine("canvas has not been activated"))?;
    if !can_record_in(&mut tx, actor, &canvas_id, Capability::Edit).await? {
        return Ok(deny(&refusal(
            "permission_denied",
            "canvas requires edit capability",
        )));
    }
    // Assess every item against the scene as it is now.
    let head = canvas::current_version(&mut tx, &canvas_id).await?;
    let canvas_stale = expected
        .as_ref()
        .is_some_and(|pins| pins.canvas_version != head.encode());
    let mut assessments: Vec<Value> = Vec::new();
    let mut objects: Vec<SceneObject> = Vec::new();
    let mut all_accept = true;
    for item in &items {
        let loaded = canvas::load_object(&mut tx, &canvas_id, &item.object_id).await?;
        // An object the caller pinned a version for is one they had seen, so
        // its disappearance, tombstoning or conversion since is drift rather
        // than an incoherent plan -- and drift must read as stale, because
        // that is what the plan runtime turns into a 409.
        let pinned_by_caller = expected
            .as_ref()
            .is_some_and(|pins| pins.objects.contains_key(&item.object_id));
        let drift = if pinned_by_caller {
            "would_stale"
        } else {
            "would_conflict"
        };
        let (status, note) = match &loaded {
            None => (drift, "no such object on this canvas"),
            Some(object) if object.deleted => (drift, "this object is tombstoned"),
            Some(object) if object.kind == ObjectKind::RecordCard => (
                drift,
                "this object is already a record card; it names a record already",
            ),
            // A card cannot parent anything, so converting a frame that still
            // holds children would leave them pointing at a non-frame: the
            // scene would render them nested while no later batch could
            // re-parent them. Delete detaches children for exactly this
            // reason; promotion refuses instead, because dissolving someone's
            // grouping is not something they asked for.
            Some(object)
                if object.kind == ObjectKind::Frame
                    && frame_has_children(&mut tx, &canvas_id, &object.id).await? =>
            {
                (
                    "would_conflict",
                    "this frame still holds objects; a record card cannot parent them",
                )
            }
            // Nulling the connector's props would drop `semantic` while the
            // governed link it recorded stayed in place, with nothing on the
            // canvas naming it -- the same stranding assert_connector refuses.
            Some(object)
                if object.kind == ObjectKind::Connector
                    && object
                        .props
                        .get("semantic")
                        .and_then(Value::as_object)
                        .is_some_and(|semantic| {
                            semantic.get("status").and_then(Value::as_str) == Some("asserted")
                        }) =>
            {
                (
                    "would_conflict",
                    "this connector carries an asserted link; retract it before promoting",
                )
            }
            Some(object) => {
                let pinned = expected
                    .as_ref()
                    .and_then(|pins| pins.objects.get(&item.object_id));
                let drifted = pinned.is_some_and(|pins| {
                    version_moved(pins.geometry.as_deref(), object.geometry_seq)
                        || version_moved(pins.content.as_deref(), object.content_seq)
                });
                if canvas_stale || drifted {
                    (
                        "would_stale",
                        "this object has moved since the plan was made",
                    )
                } else {
                    ("would_accept", "")
                }
            }
        };
        if status != "would_accept" {
            all_accept = false;
        }
        let mut assessment = json!({
            "object_id": item.object_id,
            "status": status,
            "type": item.record_type,
            "kind": item.kind,
        });
        if !note.is_empty() {
            assessment["note"] = json!(note);
        }
        if let Some(object) = &loaded {
            assessment["versions"] = json!({
                "geometry": CanvasVersion(object.geometry_seq).encode(),
                "content": CanvasVersion(object.content_seq).encode(),
            });
            objects.push(object.clone());
        }
        assessments.push(assessment);
    }

    // Links are assessed too. A plan-required ceremony that previewed only
    // the records would let a person approve a promotion whose link names a
    // record they cannot write -- an approval spent on a plan guaranteed to
    // fail inside the transaction, after the records were already minted.
    let mut link_assessments: Vec<Value> = Vec::new();
    for link in &links {
        let from_planned = items.iter().any(|item| item.object_id == link.from);
        let to_planned = items.iter().any(|item| item.object_id == link.to);
        let (status, note) = if link.relationship.trim().is_empty() {
            ("would_conflict", "a link relationship must not be blank")
        } else if is_reserved_relationship(&link.relationship) {
            (
                "would_conflict",
                "the surface_binding relationship is reserved to manage_surface_bindings",
            )
        } else if !from_planned
            && !can_record_in(&mut tx, actor, &link.from, Capability::Edit).await?
        {
            (
                "would_conflict",
                "you may not edit the record this link starts from",
            )
        } else if !to_planned && !can_record_in(&mut tx, actor, &link.to, Capability::View).await? {
            (
                "would_conflict",
                "you may not see the record this link points at",
            )
        } else {
            ("would_accept", "")
        };
        if status != "would_accept" {
            all_accept = false;
        }
        let mut assessment = json!({
            "from": link.from,
            "to": link.to,
            "relationship": link.relationship,
            "status": status,
            "from_promoted": from_planned,
            "to_promoted": to_planned,
        });
        if !note.is_empty() {
            assessment["note"] = json!(note);
        }
        link_assessments.push(assessment);
    }

    let digest = promotion_digest(&canvas_id, &reason, head, &objects, &items, &links);

    if dry_run {
        tx.rollback().await?;
        return Ok(json!({
            "action": "promote",
            "version": PROMOTE_VERSION,
            "outcome": "planned",
            "canvas_id": canvas_id,
            "canvas_version": head.encode(),
            "plan_digest": digest,
            "items": assessments,
            "links": link_assessments,
        }));
    }

    // Execution is bound to the plan. Both refusals are Error::Conflict rather
    // than a 200 outcome: the executor's plan runtime keys `plan_stale` off a
    // diagnostic containing "revision conflict", and a hosted caller needs the
    // 409 to tell a stale plan from a rejected one.
    let Some(supplied) = plan_digest else {
        tx.rollback().await?;
        return Err(Error::engine(
            "promote: executing a plan requires the plan_digest a dry run returned",
        ));
    };
    if supplied != digest || !all_accept {
        tx.rollback().await?;
        return Err(Error::conflict(format!(
            "promote: revision conflict; the canvas moved since the plan was made \
             (plan {supplied}, current {digest}). Prepare again."
        )));
    }

    let mut acts = crate::act::ActAllocation::new();
    let pending = kernel::app_installs::start_app_action_in(
        db,
        &mut tx,
        actor,
        "manage_canvas",
        crate::canonical_json::digest_json(
            &json!({"app":kernel::app_installs::dispatched_identity(),"arguments":arguments}),
        ),
        Some(reason.clone()),
        &mut acts,
    )
    .await?;
    let event_id = uuid::Uuid::new_v4().to_string();
    let canvas_record = kernel::read_record_on(&mut tx, actor, &canvas_id)
        .await?
        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    // v1 defaults to filing placement, which can differ from the canvas's
    // private policy home. Reuse the ordinary wire/lifecycle mapping.
    let canvas_filing =
        kernel::v1_state::lifecycle_bearer_on(&mut tx, &canvas_record.home_id, Some(&canvas_id))
            .await?;
    let mut minted: BTreeMap<String, String> = BTreeMap::new();
    for item in &items {
        if item.record_type == "Message" {
            return Err(Error::engine("promote cannot create a Message"));
        }
        let mut args = json!({"type":item.record_type,"kind":item.kind,"reason":reason,
            "home_id":item.home_id.as_deref().unwrap_or(&canvas_filing),
            "links":[{"target_id":canvas_id,"relationship":"derived_from","note":format!("promoted from this canvas: {reason}")}]});
        if let Some(name) = &item.name {
            args["name"] = json!(name);
        }
        if let Some(summary) = &item.summary {
            args["summary"] = json!(summary);
        }
        if let Some(facets) = &item.facets {
            args["facets"] = json!(facets);
        }
        let created = writes::create_with_origin(db, &mut tx, &mut acts, actor, &args,
            json!({"canvas_id":canvas_id,"object_id":item.object_id,"promotion_event_id":event_id,"plan_digest":digest})).await?;
        minted.insert(
            item.object_id.clone(),
            created["id"]
                .as_str()
                .ok_or_else(|| Error::engine("promotion create missing id"))?
                .into(),
        );
    }
    for link in &links {
        let source = minted.get(&link.from).unwrap_or(&link.from);
        let target = minted.get(&link.to).unwrap_or(&link.to);
        writes::change_link(
            db,
            &mut tx,
            &mut acts,
            actor,
            source,
            target,
            &link.relationship,
            false,
            link.note.as_deref(),
        )
        .await?;
    }
    let mut ops = Vec::new();
    for object in &objects {
        let mut props: Map<String, Value> = object
            .props
            .keys()
            .map(|key| (key.clone(), Value::Null))
            .collect();
        props.insert("record_id".into(), json!(minted[&object.id]));
        props.insert(
            "promoted_from".into(),
            json!({"object_id":object.id,"attestation_id":event_id}),
        );
        ops.push(Op::Patch {
            id: object.id.clone(),
            expected: Expected {
                geometry: None,
                content: Some(CanvasVersion(object.content_seq).encode()),
            },
            set: PatchSet {
                props: Some(props),
                kind: Some(ObjectKind::RecordCard),
                ..Default::default()
            },
        });
    }
    let envelope = BatchEnvelope {
        version: BATCH_VERSION.into(),
        canvas_id: canvas_id.clone(),
        batch_id: uuid::Uuid::new_v4().to_string(),
        base_version: Some(head.encode()),
        origin: Origin {
            kind: OriginKind::Promotion,
            gesture: None,
            undo_of: None,
            note: Some(reason.clone()),
        },
        ops,
    };
    let next: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0)+1 FROM content_events")
        .fetch_one(&mut *tx)
        .await?;
    let position = kernel::canvas_v2::public_position(floor, next)?;
    let stored = match kernel::canvas_v2::prepare_promotion(&mut tx, &envelope, position).await? {
        kernel::canvas_v2::PreparedBatch::Ready(stored) => stored,
        kernel::canvas_v2::PreparedBatch::Conflicts(_) => {
            return Err(Error::conflict("promote: revision conflict; prepare again"))
        }
    };
    let event = crate::store::append_with_event_id_in(
        db,
        &mut tx,
        event_id,
        crate::store::AppendSpec {
            record_id: canvas_id.clone(),
            event_type: kernel::canvas_v2::BATCH.into(),
            payload: serde_json::to_value(&stored)?,
            actor: Some(actor.into()),
        },
        &mut acts,
    )
    .await?;
    let position = kernel::canvas_v2::public_position(floor, event.local_seq)?;
    for (object_id, record_id) in &minted {
        crate::store::append_in(db, &mut tx, crate::store::AppendSpec { record_id:record_id.clone(),event_type:"kernel.facet_observed.v1".into(),actor:Some(actor.into()),
            payload:serde_json::to_value(kernel::FacetObservation { key:PROMOTED_FROM_FACET_KEY.into(),
                value:Some(json!({"canvas_id":canvas_id,"object_id":object_id,"batch_event_id":event.id,"attestation_id":event.id}).to_string()),
                value_num:None, vocab_ref:None, as_of:event.created_at.clone() })? }, &mut acts).await?;
    }
    let mut output = json!({"action":"promote","version":PROMOTE_VERSION,"outcome":"committed","canvas_id":canvas_id,
        "canvas_version":CanvasVersion(position).encode(),"event_id":event.id,"batch_id":stored.batch_id,"plan_digest":digest,
        "promoted":minted.iter().map(|(object_id,record_id)| json!({"object_id":object_id,"record_id":record_id})).collect::<Vec<_>>(),
        "objects":canvas::versions_after(position,&stored.ops,&stored.pre_images,&stored.detached),"conflicts":[],"act":acts.get()});
    if let Some(attribution) =
        kernel::app_installs::finish_app_action_in(db, &mut tx, actor, pending, &mut acts).await?
    {
        output["app_attribution"] = attribution;
    }
    db.commit_kernel_content(tx).await?;
    Ok(output)
}
