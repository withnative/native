//! Ordinary messaging executor operations over kernel-owned authority and state.
use super::*;
use crate::{
    act::ActAllocation,
    authorization::Capability,
    db::begin_write,
    store::{append_in, AppendSpec},
};
use kernel::messaging as m;
pub(super) use kernel::messaging::expectation_value;
use sqlx::{Sqlite, Transaction};
use std::collections::{BTreeMap, BTreeSet};

fn invalid(detail: &str) -> Error {
    Error::engine(format!("manage_messages (kernel-v2): {detail}"))
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| invalid("missing or invalid text argument"))
}
fn strings(v: &Value) -> Result<Vec<String>> {
    serde_json::from_value(v.clone()).map_err(|_| invalid("expected string array"))
}
fn flag(v: &Value, key: &str) -> bool {
    v[key]
        .as_bool()
        .unwrap_or_else(|| v[key].as_i64() == Some(1))
}
fn version(v: &Value) -> i64 {
    v["version"].as_i64().unwrap_or(0)
}
fn normalized_origin(origin: &Value) -> Result<Value> {
    let mut origin = origin.clone();
    if origin["type"] == "direct" {
        let mut participants = strings(&origin["participant_ids"])?;
        let before = participants.len();
        participants.sort();
        participants.dedup();
        if participants.len() < 2 || participants.len() != before {
            return Err(invalid(
                "direct context requires at least two distinct participants",
            ));
        }
        origin["participant_ids"] = json!(participants);
    }
    Ok(origin)
}
async fn collection_origin(
    tx: &mut Transaction<'static, Sqlite>,
    actor: &str,
    id: &str,
) -> Result<()> {
    if id == "native:root" {
        return kernel::kernel_require(tx, actor, crate::events::KERNEL_ROOT_ID, Capability::View)
            .await;
    }
    let view = kernel::read_record_on(tx, actor, id)
        .await?
        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    if view.fields.get("v1_type").and_then(Value::as_str) != Some("Collection") {
        return Err(invalid("origin must be a Collection"));
    }
    Ok(())
}

async fn require(
    tx: &mut Transaction<'static, Sqlite>,
    actor: &str,
    id: &str,
) -> Result<kernel::MessageState> {
    kernel::kernel_require(tx, actor, id, Capability::View).await?;
    m::on(tx, id)
        .await?
        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))
}
async fn append(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut ActAllocation,
    actor: &str,
    id: &str,
    kind: &str,
    value: Value,
) -> Result<()> {
    let spec = AppendSpec {
        record_id: id.into(),
        event_type: kind.into(),
        payload: value,
        actor: Some(actor.into()),
    };
    if kind == kernel::notifications::PREFERENCE_EVENT {
        crate::store::append_kernel_notification_preference_in(db, tx, spec, acts).await?;
        return Ok(());
    }
    append_in(db, tx, spec, acts).await?;
    Ok(())
}
async fn head(tx: &mut Transaction<'static, Sqlite>) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM main.content_events")
            .fetch_one(&mut **tx)
            .await?,
    )
}
async fn person(tx: &mut Transaction<'static, Sqlite>, actor: &str, id: &str) -> Result<String> {
    // Transport names portable Person records; auth bindings never come from input.
    kernel::kernel_require(tx, actor, id, Capability::View).await?;
    sqlx::query_scalar("SELECT principal_id FROM kernel_message_people WHERE person_id=?")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| invalid("recipient has no verified messaging identity"))
}

pub(super) async fn execute(db: &Db, actor: &str, caller: &Caller, args: Value) -> Result<Value> {
    let action = text(&args, "action")?;
    if action == "get_notification_preference" {
        // The transport enum's unit read variant accepts extra fields. Close
        // this private read explicitly: no supplied selector is meaningful,
        // even when it would otherwise be ignored in favour of the caller.
        if args
            .as_object()
            .is_some_and(|args| args.keys().any(|key| key != "action"))
        {
            return Err(invalid("get_notification_preference accepts only action; its subject is the authenticated account"));
        }
        let mut tx = db.pool().begin().await?;
        kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
        kernel::notifications::require_account_on(&mut tx, actor).await?;
        return Ok(
            json!({"arrival":kernel::notifications::arrival_on(&mut tx, actor).await?,
            "values":crate::control::NOTIFICATION_ARRIVAL_VALUES}),
        );
    }
    if matches!(
        action,
        "list_context"
            | "list_message_state"
            | "list_conversation"
            | "list_unclassified"
            | "list_my_conversations"
            | "list_inbox"
            | "get_attention"
            | "list_destinations"
            | "list_notification_candidates"
    ) {
        return read(db, actor, args).await;
    }
    // These operations are deliberately outside this executor slice.
    if matches!(action, "share_history" | "delete" | "edit") {
        return Err(unsupported(
            "manage_messages",
            "history sharing, message editing and deletion and live notification delivery",
        ));
    }
    let classification = matches!(action, "classify" | "unclassify" | "move");
    let key = if classification {
        args["idempotency_key"].as_str().unwrap_or("")
    } else {
        text(&args, "idempotency_key")?
    };
    if (key.trim().is_empty() && (!classification || args["idempotency_key"].is_string()))
        || key.chars().count() > 200
    {
        return Err(invalid("idempotency_key must be 1..200 characters"));
    }
    if !classification && text(&args, "reason")?.trim().is_empty() {
        return Err(invalid("reason must not be blank"));
    }
    // Existing member receipts retain their digest; app receipts bind the exact
    // install identity and can never replay a member's or another app's write.
    let app = kernel::app_installs::dispatched_identity();
    let attributed = app.is_some();
    let request = crate::interventions::sha256_json(&if app.is_some() {
        json!({"app":app,"arguments":args})
    } else {
        args.clone()
    })?;
    let mut tx = begin_write(db.write_pool()).await?;
    m::ensure_schema(&mut tx).await?;
    if action == "set_notification_preference"
        && !kernel::hosted_identity::admitted(&mut tx, actor).await?
    {
        return Err(invalid("database membership not found"));
    }
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    if action == "set_notification_preference" {
        kernel::notifications::require_account_on(&mut tx, actor).await?;
    }
    let old:Option<(String,String)>=sqlx::query_as("SELECT request,receipt FROM kernel_message_receipts WHERE principal_id=? AND operation_key=?")
        .bind(actor).bind(key).fetch_optional(&mut *tx).await?;
    if let Some((old, receipt)) = old {
        if old != request {
            return Err(Error::conflict(
                "idempotency_key reused for different messaging intent",
            ));
        }
        let receipt: Value = serde_json::from_str(&receipt)?;
        if action == "send" && args.get("speaker").is_some() {
            resolve_speaker(&mut tx, actor, args.get("speaker")).await?;
        }
        if receipt["collection_id"].is_string() {
            if receipt["present"] == true {
                collection_origin(&mut tx, actor, text(&receipt, "collection_id")?).await?;
            }
        } else if receipt["message_ids"].is_array() {
            for id in strings(&receipt["message_ids"])? {
                require(&mut tx, actor, &id).await?;
            }
        } else if action != "set_notification_preference" {
            require(&mut tx, actor, text(&receipt, "message_id")?).await?;
        }
        for target in receipt["link_targets"].as_array().into_iter().flatten() {
            kernel::kernel_require(
                &mut tx,
                actor,
                target
                    .as_str()
                    .ok_or_else(|| invalid("invalid receipt target"))?,
                Capability::View,
            )
            .await?;
        }
        tx.rollback().await?;
        return Ok(receipt);
    }
    if action == "mutate_human_awareness" {
        let proof = caller.verified_human_interaction().ok_or_else(|| {
            invalid("human awareness requires a server-verified interaction attestation")
        })?;
        let used:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_message_interactions WHERE principal_id=? AND nonce=?)").bind(actor).bind(&proof.nonce).fetch_one(&mut *tx).await?;
        if used {
            return Err(invalid("human interaction nonce already used"));
        }
    }
    let mut acts = ActAllocation::new();
    let pending = kernel::app_installs::start_app_action_in(
        db,
        &mut tx,
        actor,
        "manage_messages",
        request.clone(),
        args["reason"].as_str().map(str::to_owned),
        &mut acts,
    )
    .await?;
    let mut receipt = if action == "set_notification_preference" {
        let arrival = text(&args, "arrival")?;
        let previous = kernel::notifications::arrival_on(&mut tx, actor).await?;
        let changed = previous != arrival;
        // Record accepted intent even when the value is unchanged. The
        // command receipt below reserves the retry key in the same transaction.
        append(
            db,
            &mut tx,
            &mut acts,
            actor,
            actor,
            kernel::notifications::PREFERENCE_EVENT,
            json!({"arrival":arrival}),
        )
        .await?;
        json!({"arrival":arrival,"changed":changed,"idempotent":false})
    } else if matches!(
        action,
        "mark_no_longer_relevant" | "unmark_no_longer_relevant"
    ) {
        relevance(db, &mut tx, &mut acts, actor, &args).await?
    } else if action == "send" {
        send(db, &mut tx, &mut acts, actor, &args).await?
    } else if action == "set_destination" {
        let collection = text(&args, "collection_id")?;
        let present = match text(&args, "destination")? {
            "add" => true,
            "remove" => false,
            _ => return Err(invalid("destination must be add or remove")),
        };
        if present {
            collection_origin(&mut tx, actor, collection).await?;
        }
        let old = m::destination_on(&mut tx, actor, collection)
            .await?
            .unwrap_or(Value::Null);
        if args["expected_version"].as_i64() != Some(version(&old)) {
            return Err(Error::conflict("destination version conflict"));
        }
        let changed = flag(&old, "present") != present;
        if changed {
            let mut state = if old.is_object() {
                old.clone()
            } else {
                json!({})
            };
            state["collection_id"] = json!(collection);
            state["subject_account_id"] = json!(caller.credential());
            state["present"] = json!(present);
            state["version"] = json!(version(&old) + 1);
            state["joined_by"] = json!(if present {
                "explicit"
            } else {
                old["joined_by"].as_str().unwrap_or("explicit")
            });
            state["joined_at"] = if present {
                json!(crate::store::now_iso())
            } else {
                Value::Null
            };
            append(
                db,
                &mut tx,
                &mut acts,
                actor,
                actor,
                m::DEST_SET,
                serde_json::to_value(m::Destination {
                    principal_id: actor.into(),
                    collection_id: collection.into(),
                    state,
                })?,
            )
            .await?;
        }
        json!({"collection_id":collection,"present":present,"version":version(&old)+i64::from(changed),"changed":changed})
    } else if action == "mutate_human_awareness" {
        let ids = strings(&args["message_ids"])?;
        if ids.is_empty()
            || ids.len() > 500
            || ids.iter().collect::<BTreeSet<_>>().len() != ids.len()
        {
            return Err(invalid("human awareness requires 1..500 unique ids"));
        }
        let versions = args["expected_versions"]
            .as_object()
            .ok_or_else(|| invalid("expected_versions must match exact ids"))?;
        if versions.len() != ids.len() || ids.iter().any(|id| !versions.contains_key(id)) {
            return Err(invalid("expected_versions must match exact ids"));
        }
        if ids.len() > 1 {
            let snapshot = db.get_inbox_snapshot(text(&args, "snapshot")?)?;
            let pinned = strings(&snapshot["ids"])?;
            if snapshot["actor"] != actor
                || snapshot["action"] != "list_inbox"
                || ids.iter().any(|id| !pinned.contains(id))
            {
                return Err(invalid(
                    "awareness batch requires caller's pinned Inbox snapshot",
                ));
            }
        }
        let stage: crate::awareness::HumanStage = serde_json::from_value(args["stage"].clone())
            .map_err(|_| invalid("invalid human stage"))?;
        if stage == crate::awareness::HumanStage::Unsurfaced {
            return Err(invalid("cannot regress to unsurfaced"));
        }
        let mut results = Vec::new();
        for id in &ids {
            let mut state = require(&mut tx, actor, id).await?;
            let old = lane(&state, actor, "human");
            if versions[id].as_i64() != Some(version(&old)) {
                return Err(Error::conflict("human awareness version conflict"));
            }
            let current: crate::awareness::HumanStage =
                serde_json::from_value(old.get("stage").cloned().unwrap_or(json!("unsurfaced")))
                    .map_err(|_| invalid("invalid stored stage"))?;
            let next = stage.advanced(current);
            if next == current {
                results.push(json!({"message_id":id,"stage":current,"version":version(&old),"changed":false}));
                continue;
            }
            let now = crate::store::now_iso();
            let mut human = old.clone();
            if !human.is_object() {
                human = json!({});
            }
            let proof = caller
                .verified_human_interaction()
                .ok_or_else(|| invalid("human attestation missing"))?;
            human["executor_ref"] = json!(proof.executor_ref);
            human["interaction_nonce"] = json!(proof.nonce);
            human["stage"] = serde_json::to_value(next)?;
            human["version"] = json!(version(&old) + 1);
            if stage == crate::awareness::HumanStage::Presented {
                human["last_presented_at"] = json!(now);
                if human["first_presented_at"].is_null() {
                    human["first_presented_at"] = json!(now);
                }
            }
            if matches!(
                next,
                crate::awareness::HumanStage::Opened | crate::awareness::HumanStage::Acknowledged
            ) && human["opened_at"].is_null()
            {
                human["opened_at"] = json!(now);
            }
            if next == crate::awareness::HumanStage::Acknowledged
                && human["acknowledged_at"].is_null()
            {
                human["acknowledged_at"] = json!(now);
            }
            state
                .private
                .entry(actor.into())
                .or_default()
                .insert("human".into(), human.clone());
            append(
                db,
                &mut tx,
                &mut acts,
                actor,
                id,
                m::EVENT,
                serde_json::to_value(state)?,
            )
            .await?;
            results.push(
                json!({"message_id":id,"stage":next,"version":version(&human),"changed":true}),
            );
        }
        let changed = results.iter().any(|row| row["changed"] == true);
        json!({"status":if changed {"applied"} else {"unchanged"},"results":results,"exact_message_ids":ids,"message_ids":ids,"changed":changed})
    } else {
        let id = text(&args, "message_id")?;
        let mut state = require(&mut tx, actor, id).await?;
        let previous = state.clone();
        match action {
            "satisfy_acknowledgement_expectation_with_reaction" => {
                let recipient: Option<String> = sqlx::query_scalar(
                    "SELECT person_id FROM kernel_message_people WHERE principal_id=?",
                )
                .bind(actor)
                .fetch_optional(&mut *tx)
                .await?;
                if state.expectation.as_deref() != Some("ack")
                    || !recipient.is_some_and(|p| state.addressed_to.contains(&p))
                {
                    return Err(invalid("no acknowledgement expectation for caller"));
                }
                state.acknowledgements.insert(actor.into(), id.into());
                let reactions = state.reactions.entry(actor.into()).or_default();
                if !reactions.iter().any(|e| e == "👍") {
                    reactions.push("👍".into());
                    reactions.sort();
                }
                // Like v1, acknowledging also closes the acknowledger's routing,
                // so an obligation reopened since an earlier acknowledgement is
                // closed again by a fresh one. The routing transition is what
                // the projector withdraws on; it is a no-op when already closed.
                let lanes = state.private.entry(actor.into()).or_default();
                let old = lanes.get("routing").cloned().unwrap_or(Value::Null);
                if old["obligation_state"] != "satisfied" || old["executor_route"] != "closed" {
                    lanes.insert("routing".into(), json!({"obligation_state":"satisfied","executor_route":"closed","policy_version":null,"version":version(&old)+1,"reason_code":args["reason"]}));
                }
            }
            "set_routing" => {
                let obligation = text(&args, "obligation_state")?;
                let route = text(&args, "executor_route")?;
                if !["none", "open", "satisfied", "withdrawn"].contains(&obligation)
                    || !["unassigned", "human", "agent", "joint", "closed"].contains(&route)
                {
                    return Err(invalid("invalid obligation or executor route"));
                }
                if ["agent", "joint"].contains(&route)
                    && args["policy_version"].as_str().is_none_or(str::is_empty)
                {
                    return Err(invalid("agent routing requires a versioned policy"));
                }
                let lanes = state.private.entry(actor.into()).or_default();
                let old = lanes.get("routing").cloned().unwrap_or(Value::Null);
                if args["expected_version"].as_i64() != Some(version(&old)) {
                    return Err(Error::conflict("routing version conflict"));
                }
                lanes.insert("routing".into(),json!({"obligation_state":obligation,"executor_route":route,"policy_version":args["policy_version"],"version":version(&old)+1,"reason_code":args["reason"]}));
            }
            "add_reaction" | "remove_reaction" => {
                let emoji = text(&args, "emoji")?;
                if !["👍", "❤️", "😂", "🎉", "👀"].contains(&emoji) {
                    return Err(invalid("unsupported emoji"));
                }
                let reactions = state.reactions.entry(actor.into()).or_default();
                reactions.retain(|e| e != emoji);
                if action == "add_reaction" {
                    reactions.push(emoji.into());
                    reactions.sort();
                }
                if reactions.is_empty() {
                    state.reactions.remove(actor);
                }
            }
            "set_preference" => {
                let lanes = state.private.entry(actor.into()).or_default();
                let p=lanes.entry("preference".into()).or_insert_with(||json!({"version":0,"attention_flag":0,"muted":0,"archived":0,"snoozed_until":null,"unread_override":null}));
                if args["expected_version"].as_i64() != Some(version(p)) {
                    return Err(Error::conflict("preference version conflict"));
                }
                match text(&args, "preference")? {
                    "mark_read" => p["unread_override"] = json!(0),
                    "mark_unread" => p["unread_override"] = json!(1),
                    "flag_attention" => p["attention_flag"] = json!(1),
                    "clear_attention" => p["attention_flag"] = json!(0),
                    "mute" => p["muted"] = json!(1),
                    "unmute" => p["muted"] = json!(0),
                    "archive" => p["archived"] = json!(1),
                    "restore" => p["archived"] = json!(0),
                    "clear_snooze" => p["snoozed_until"] = Value::Null,
                    "snooze" => {
                        let until = text(&args, "snoozed_until")?;
                        let instant = chrono::DateTime::parse_from_rfc3339(until)
                            .map_err(|_| invalid("invalid snoozed_until"))?;
                        if instant <= chrono::Utc::now() {
                            return Err(invalid("snoozed_until must be in the future"));
                        }
                        p["snoozed_until"] = json!(until);
                    }
                    _ => return Err(invalid("invalid preference")),
                }
                p["version"] = json!(version(p) + 1);
                p["last_action"] = json!(text(&args, "preference")?);
            }
            "set_agent_disposition" => {
                let disposition = text(&args, "state")?;
                if !["triaged", "deferred", "escalated", "acted", "resolved"].contains(&disposition)
                {
                    return Err(invalid("invalid agent disposition"));
                }
                let evidence: Vec<crate::awareness::EvidenceInput> =
                    serde_json::from_value(args.get("evidence").cloned().unwrap_or(json!([])))
                        .map_err(|_| invalid("invalid evidence"))?;
                let derived = expectation_value(&mut tx, actor, id, &state).await?;
                let mut governed = false;
                for item in &evidence {
                    if !["reply", "work", "decision", "resolution", "other"]
                        .contains(&item.role.as_str())
                    {
                        return Err(invalid("invalid evidence role"));
                    }
                    let view = kernel::read_record_on(&mut tx, actor, &item.record_id)
                        .await?
                        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
                    let linked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_generic_links WHERE source_id=? AND target_id=? AND active=1 AND relationship=?)").bind(&item.record_id).bind(id).bind(if item.role=="reply" {"reply_to"} else {"derived_from"}).fetch_one(&mut *tx).await?;
                    governed |= (derived["state"] == "satisfied"
                        && derived["evidence"]["record_id"] == item.record_id)
                        || (linked
                            && view.owner_id.as_deref() == Some(actor)
                            && item.role != "other");
                }
                if ["acted", "resolved"].contains(&disposition)
                    && (!governed || evidence.is_empty())
                {
                    return Err(invalid(
                        "acted/resolved agent disposition requires exact governed evidence",
                    ));
                }
                let verified = caller
                    .verified_agent_executor()
                    .ok_or_else(|| invalid("agent executor attestation missing"))?;
                let lanes = state.private.entry(actor.into()).or_default();
                let old = lanes.get("agent").cloned().unwrap_or(Value::Null);
                if args["expected_version"].as_i64() != Some(version(&old)) {
                    return Err(Error::conflict("agent version conflict"));
                }
                lanes.insert("agent".into(),json!({"state":disposition,"version":version(&old)+1,"reason_code":args["reason"],"evidence":evidence.iter().map(|e|json!({"record_id":e.record_id,"role":e.role})).collect::<Vec<_>>(),"last_executor_ref":verified.executor_ref,"delegation_ref":verified.delegation_ref}));
            }
            "classify" | "unclassify" | "move" => {
                kernel::kernel_require(&mut tx, actor, id, Capability::Edit).await?;
                if action == "move" {
                    let from = text(&args, "from_conversation_id")?;
                    if !state.conversations.iter().any(|c| c == from) {
                        return Err(invalid("source classification missing"));
                    }
                    state.conversations.retain(|c| c != from);
                }
                let conversation = text(
                    &args,
                    if action == "move" {
                        "to_conversation_id"
                    } else {
                        "conversation_id"
                    },
                )?;
                let view = kernel::read_record_on(&mut tx, actor, conversation)
                    .await?
                    .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
                if view.fields.get("v1_type").and_then(Value::as_str) != Some("Conversation") {
                    return Err(invalid("classification target must be a Conversation"));
                }
                state.conversations.retain(|c| c != conversation);
                if action != "unclassify" {
                    state.conversations.push(conversation.into());
                    state.conversations.sort();
                }
            }
            _ => return Err(unsupported("manage_messages", action)),
        }
        let changed = state != previous;
        if changed {
            append(
                db,
                &mut tx,
                &mut acts,
                actor,
                id,
                m::EVENT,
                serde_json::to_value(&state)?,
            )
            .await?;
            for target in previous
                .conversations
                .iter()
                .filter(|c| !state.conversations.contains(c))
            {
                kernel::generic_links::remove_generic_link_triple_in(
                    db,
                    &mut tx,
                    &mut acts,
                    actor,
                    id,
                    target,
                    "participates_in",
                )
                .await?;
            }
            for target in state
                .conversations
                .iter()
                .filter(|c| !previous.conversations.contains(c))
            {
                kernel::generic_links::add_generic_link_in(
                    db,
                    &mut tx,
                    &mut acts,
                    actor,
                    id,
                    target,
                    "participates_in",
                    None,
                )
                .await?;
            }
        }
        let lane = state.private.get(actor).and_then(|p| {
            p.get(match action {
                "set_routing" => "routing",
                "set_agent_disposition" => "agent",
                _ => "preference",
            })
        });
        let mut result = json!({"status":if changed {"updated"} else {"unchanged"},"message_id":id,"changed":changed,"idempotent":false,"version":lane.map(version)});
        if matches!(action, "add_reaction" | "remove_reaction") {
            result["emoji"] = args["emoji"].clone();
            result["status"] = json!(if !changed {
                "unchanged"
            } else if action == "add_reaction" {
                "added"
            } else {
                "removed"
            });
        } else if action == "set_preference" {
            let preference = lane.unwrap();
            for key in ["attention_flag", "muted", "archived"] {
                result[key] = json!(flag(preference, key));
            }
            result["unread_override"] = preference["unread_override"]
                .as_bool()
                .or_else(|| preference["unread_override"].as_i64().map(|v| v != 0))
                .map_or(Value::Null, Value::Bool);
            result["snoozed_until"] = preference["snoozed_until"].clone();
        } else if action == "satisfy_acknowledgement_expectation_with_reaction" {
            result["status"] = json!("acknowledged");
            result["emoji"] = json!("👍");
            result["message_expectation_state"] =
                expectation_value(&mut tx, actor, id, &state).await?;
        } else if matches!(action, "set_routing" | "set_agent_disposition") {
            if let Some(lane) = lane.and_then(Value::as_object) {
                for (key, value) in lane {
                    result[key] = value.clone();
                }
            }
        }
        result
    };
    if receipt["changed"] != false && !matches!(action, "send" | "set_notification_preference") {
        let (seq, event_id, act, record_id): (i64, String, Option<i64>, String) = sqlx::query_as(
            "SELECT seq,id,act,record_id FROM main.content_events ORDER BY seq DESC LIMIT 1",
        )
        .fetch_one(&mut *tx)
        .await?;
        receipt["act"] = json!(act);
        receipt["write_receipt"] = json!({"kind":"kernel_content_event","event":{"seq":seq,"event_id":event_id,"record_id":record_id}});
    }
    if matches!(
        action,
        "mark_no_longer_relevant" | "unmark_no_longer_relevant"
    ) {
        // v1 also anchors a no-op undo as an accepted act. The command event
        // below is its durable witness without touching the Message clock.
        receipt["act"] = json!(acts.get_or_allocate(&mut tx).await?);
    }
    if let Some(attribution) =
        kernel::app_installs::finish_app_action_in(db, &mut tx, actor, pending, &mut acts).await?
    {
        receipt["app_attribution"] = attribution;
    }
    let unchanged_awareness = action == "mutate_human_awareness" && receipt["changed"] == false;
    if !key.is_empty() && (!unchanged_awareness || attributed) {
        let nonce = if action == "mutate_human_awareness" {
            caller.verified_human_interaction().map(|p| p.nonce.clone())
        } else {
            None
        };
        append(
            db,
            &mut tx,
            &mut acts,
            actor,
            actor,
            m::COMMAND,
            serde_json::to_value(m::CommandReceipt {
                operation_key: key.into(),
                request,
                receipt: receipt.clone(),
                nonce,
            })?,
        )
        .await?;
    }
    db.commit_kernel_content(tx).await?;
    if let Some(hub) = db.realtime_hub() {
        hub.wake();
    }
    Ok(receipt)
}

async fn send(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut ActAllocation,
    actor: &str,
    args: &Value,
) -> Result<Value> {
    let body = text(args, "body")?;
    if body.trim().is_empty() {
        return Err(invalid("body must not be blank"));
    }
    if args.get("preview").is_some() {
        return Err(unsupported("manage_messages.send", "disclosure preview"));
    }
    if args.get("owner_id").is_some() {
        return Err(unsupported("manage_messages.send", "owner_id override"));
    }
    let expectation = text(args, "expectation")?;
    if !crate::message_expectation::EXPECTATION_VALUES.contains(&expectation) {
        return Err(invalid("invalid expectation"));
    }
    let addressed = strings(&args["addressed_to"])?;
    if addressed.is_empty() && expectation != "none" {
        return Err(invalid("an empty addressed_to requires expectation none"));
    }
    if addressed.iter().collect::<BTreeSet<_>>().len() != addressed.len() {
        return Err(invalid("duplicate addressed_to"));
    }
    let mut state = kernel::MessageState {
        author: Some(actor.into()),
        origin: normalized_origin(&args["origin"])?,
        addressed_to: addressed.clone(),
        expectation: Some(expectation.into()),
        ..Default::default()
    };
    let rules:Option<String>=sqlx::query_scalar("SELECT json_extract(state,'$.rules') FROM kernel_messages WHERE json_type(state,'$.rules')='object' ORDER BY event_seq DESC LIMIT 1").fetch_optional(&mut **tx).await?;
    state.rules = rules.map(|raw| serde_json::from_str(&raw)).transpose()?;
    if matches!(expectation, "action" | "decision") && state.rules.is_none() {
        return Err(unsupported(
            "manage_messages.send",
            "action/decision expectation rules have not been imported",
        ));
    }
    state.audience.insert(actor.into(), "manage".into());
    for id in &addressed {
        let p = person(tx, actor, id).await?;
        if p != actor {
            state.audience.insert(p, "view".into());
        }
    }
    let original_home = match text(&args["origin"], "type")? {
        "collection" => {
            let collection = text(&args["origin"], "collection_id")?;
            collection_origin(tx, actor, collection).await?;
            collection.to_owned()
        }
        "direct" => {
            let participants = strings(&args["origin"]["participant_ids"])?;
            let mut resolved = BTreeSet::new();
            for id in participants {
                resolved.insert(person(tx, actor, &id).await?);
            }
            if resolved.len() < 2 || !resolved.contains(actor) {
                return Err(invalid(
                    "direct context requires caller and another principal",
                ));
            }
            if !state.audience.keys().all(|p| resolved.contains(p)) {
                return Err(invalid(
                    "addressed recipients must belong to direct context",
                ));
            }
            "native:unfiled".into()
        }
        _ => return Err(invalid("invalid communication origin")),
    };
    state.home_id = Some(args["home_id"].as_str().unwrap_or(&original_home).into());
    if let Some(home) = args["home_id"].as_str() {
        if home != "native:unfiled" {
            crate::v1_import::resolve_home_on(tx, actor, home).await?;
        }
    }
    state.speaker = resolve_speaker(tx, actor, args.get("speaker")).await?;
    if state.speaker.is_none() {
        for id in &addressed {
            if person(tx, actor, id).await? == actor {
                return Err(invalid("self-addressing requires a speaker claim"));
            }
        }
    }
    let inputs: Vec<crate::awareness::MentionInput> = args
        .get("mentions")
        .filter(|v| !v.is_null())
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()?
        .unwrap_or_default();
    let mut mention_ids = BTreeSet::new();
    for mention in inputs {
        if mention.mention_id.trim().is_empty() || !mention_ids.insert(mention.mention_id.clone()) {
            return Err(invalid("mention ids must be non-empty and unique"));
        }
        crate::awareness::validate_mention_span(body, &mention)?;
        kernel::kernel_require(tx, actor, &mention.target_id, Capability::View).await?;
        let binding = match mention.target_kind.as_str() {
            "principal" => {
                let principal = person(tx, actor, &mention.target_id).await?;
                if !addressed.contains(&mention.target_id) {
                    // A mention alerts a person without addressing them or
                    // changing who can read the Message. That only holds where
                    // the Message inherits its audience, a Collection origin,
                    // and only for someone who already sees that Collection.
                    // A direct context's readers are its exact participants.
                    if state.origin["type"] != "collection" {
                        return Err(invalid(
                            "principal mention target must already be addressed",
                        ));
                    }
                    let collection = match text(&state.origin, "collection_id")? {
                        "native:root" => crate::events::KERNEL_ROOT_ID,
                        id => id,
                    };
                    if !kernel::kernel_effective_capability_on(tx, &principal, collection)
                        .await?
                        .allows(Capability::View)
                    {
                        return Err(invalid(
                            "a mentioned person who is not addressed must be able to see the Collection the Message is posted in; the mention is refused and access is unchanged",
                        ));
                    }
                }
                format!("native/{principal}")
            }
            "record" => {
                let origin = if let Some(origin) = &state.mention_origin {
                    origin.clone()
                } else {
                    let existing: Option<String> = sqlx::query_scalar("SELECT json_extract(state,'$.mention_origin') FROM kernel_messages WHERE json_type(state,'$.mention_origin')='text' ORDER BY event_seq LIMIT 1").fetch_optional(&mut **tx).await?;
                    let origin = state
                        .rules
                        .as_ref()
                        .and_then(|r| r.source_origin.clone())
                        .filter(|o| crate::identity::is_database_id(o))
                        .or(existing)
                        .unwrap_or_else(crate::identity::mint_database_id);
                    state.mention_origin = Some(origin.clone());
                    origin
                };
                crate::identity::encode_native_record(&origin, &mention.target_id)?
            }
            _ => return Err(invalid("mention target_kind must be principal or record")),
        };
        let mut value = serde_json::to_value(&mention)?;
        value["target_binding"] = json!(binding);
        value["effective"] = json!(true);
        state.mentions.push(value);
    }
    let mut links: Vec<Value> = addressed
        .iter()
        .map(|id| json!({"target_id":id,"relationship":"addressed_to"}))
        .collect();
    if let Some(input) = args.get("links") {
        for link in input.as_array().ok_or_else(|| invalid("invalid links"))? {
            if link["relationship"] != "reply_to" || state.reply_to.is_some() {
                return Err(unsupported(
                    "manage_messages.send",
                    "links other than one reply_to",
                ));
            }
            let target = text(link, "target_id")?;
            let parent = require(tx, actor, target).await?;
            if parent.origin != state.origin {
                return Err(invalid("reply must retain communication origin"));
            }
            // Ordinary View on the parent and the same immutable origin
            // govern replies; addressing can differ within that origin.
            state.reply_to = Some(target.into());
            links.push(link.clone());
        }
    }
    let home = if state.origin["type"] == "collection" {
        let collection = text(&state.origin, "collection_id")?;
        if collection == "native:root" {
            crate::events::KERNEL_ROOT_ID.into()
        } else {
            let mapped: Option<String> = sqlx::query_scalar("SELECT record_id FROM main.content_events WHERE type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(payload,'$.source_record_id')=? LIMIT 1")
                .bind(collection).fetch_optional(&mut **tx).await?;
            match mapped {
                Some(home) => home,
                None => {
                    kernel::read_record_on(tx, actor, collection)
                        .await?
                        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?
                        .home_id
                }
            }
        }
    } else {
        // Direct visibility includes every participant, independently of addressing.
        let mut entries = vec![json!({"subject_id":actor,"capability":"manage"})];
        for participant in strings(&state.origin["participant_ids"])? {
            let principal = person(tx, actor, &participant).await?;
            if principal != actor {
                entries.push(json!({"subject_id":principal,"capability":"view"}));
            }
        }
        let home = uuid::Uuid::new_v4().to_string();
        append(
            db,
            tx,
            acts,
            actor,
            &home,
            kernel::KERNEL_HOME_CREATED_EVENT,
            json!({"parent_id":crate::events::KERNEL_ROOT_ID,"owner_id":actor,"entries":entries}),
        )
        .await?;
        home
    };
    let mut create = json!({"type":"Message","kind":"text","body":body,"name":args["name"].as_str().unwrap_or("Message"),"home_id":home,"facets":{"expectation":expectation},"links":links,"reason":args["reason"]});
    if let Some(id) = args.get("id") {
        create["id"] = id.clone();
    }
    let mut receipt =
        super::writes::create_with_message(db, tx, acts, actor, &create, Some(&state)).await?;
    if state.origin["type"] == "collection" {
        let collection = text(&state.origin, "collection_id")?;
        let old = m::destination_on(tx, actor, collection)
            .await?
            .unwrap_or(Value::Null);
        if !flag(&old, "present") {
            let mut destination = if old.is_object() {
                old.clone()
            } else {
                json!({})
            };
            destination["collection_id"] = json!(collection);
            destination["present"] = json!(true);
            destination["version"] = json!(version(&old) + 1);
            destination["joined_by"] = json!("send");
            destination["joined_at"] = json!(crate::store::now_iso());
            append(
                db,
                tx,
                acts,
                actor,
                actor,
                m::DEST_SET,
                serde_json::to_value(m::Destination {
                    principal_id: actor.into(),
                    collection_id: collection.into(),
                    state: destination,
                })?,
            )
            .await?;
        }
    }
    receipt["message_id"] = receipt["id"].clone();
    receipt["speaker_claim_status"] = json!(if state.speaker.is_some() {
        "recorded"
    } else {
        "absent"
    });
    if let Some(speaker) = state.speaker {
        receipt["speaker"] = speaker;
    }

    Ok(receipt)
}

fn lane(state: &kernel::MessageState, actor: &str, lane: &str) -> Value {
    state
        .private
        .get(actor)
        .and_then(|p| p.get(lane))
        .cloned()
        .unwrap_or(Value::Null)
}
/// Caller-only flags shared by exact state and SQL. This pure part must not
/// evaluate expectations or visit other viewers' private lanes.
pub(super) fn private_fields(
    actor: &str,
    recipient: Option<&str>,
    state: &kernel::MessageState,
) -> Value {
    let human = lane(state, actor, "human");
    let preference = lane(state, actor, "preference");
    let stage = human["stage"].as_str().unwrap_or("unsurfaced");
    let own = state.author.as_deref() == Some(actor) && state.speaker.is_none();
    let unread_override = preference["unread_override"]
        .as_bool()
        .or_else(|| preference["unread_override"].as_i64().map(|v| v != 0));
    let unread = !own
        && !flag(&preference, "archived")
        && unread_override.unwrap_or(!matches!(stage, "opened" | "acknowledged"));
    let mentioned = recipient.is_some_and(|p| {
        state.mentions.iter().any(|m| {
            flag(m, "effective")
                && m["target_kind"] == "principal"
                && (m["target_id"] == p || m["target_record_id"] == p)
        })
    });
    json!({"human":{"stage":stage,"version":version(&human)},"mention":{"principal":mentioned},
        "attention":{"unread":unread,"unread_override":unread_override,"version":version(&preference),"archived":flag(&preference,"archived")}})
}

pub(super) async fn state_value(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    id: &str,
    state: &kernel::MessageState,
) -> Result<Value> {
    let mut grouped = BTreeMap::<&str, Vec<Value>>::new();
    for (principal, reactions) in &state.reactions {
        // Render participant identity only through caller-visible Person records.
        let person: Option<String> =
            sqlx::query_scalar("SELECT person_id FROM kernel_message_people WHERE principal_id=?")
                .bind(principal)
                .fetch_optional(&mut *tx)
                .await?;
        let record_id = if let Some(person) = person {
            kernel::read_record_on(tx, actor, &person)
                .await?
                .map(|r| r.id)
        } else {
            None
        };
        for emoji in reactions {
            grouped
                .entry(emoji)
                .or_default()
                .push(json!({"record_id":record_id,"viewer":principal==actor}));
        }
    }
    let reactions:Vec<Value>=grouped.into_iter().map(|(emoji,actors)|json!({"emoji":emoji,"count":actors.len(),"viewer_reacted":actors.iter().any(|a|a["viewer"]==true),"actors":actors})).collect();
    let expectation = expectation_value(tx, actor, id, state).await?;
    let recipient: Option<String> =
        sqlx::query_scalar("SELECT person_id FROM kernel_message_people WHERE principal_id=?")
            .bind(actor)
            .fetch_optional(&mut *tx)
            .await?;
    let can_ack = state.expectation.as_deref() == Some("ack")
        && expectation["state"] == "open"
        && recipient
            .as_ref()
            .is_some_and(|p| state.addressed_to.contains(p));

    let mut value = private_fields(actor, recipient.as_deref(), state);
    value["message_id"] = json!(id);
    value["reactions"] = json!(reactions);
    value["message_expectation_state"] = expectation;
    value["can_satisfy_acknowledgement"] = json!(can_ack);
    Ok(value)
}
async fn message_row(
    tx: &mut Transaction<'static, Sqlite>,
    actor: &str,
    id: &str,
    state: &kernel::MessageState,
) -> Result<Value> {
    let view = kernel::read_record_on(tx, actor, id)
        .await?
        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    let created: String = sqlx::query_scalar("SELECT created_at FROM kernel_records WHERE id=?")
        .bind(id)
        .fetch_one(&mut **tx)
        .await?;
    let home = state.home_id.clone();
    let mut row = state_value(tx, actor, id, state).await?;
    row["id"] = json!(id);
    row["type"] = json!("Message");
    row["kind"] = json!("text");
    row["name"] = json!(view.fields.get("title"));
    row["body"] = json!(view.body);
    row["created_at"] = json!(state.created_at.as_ref().unwrap_or(&created));
    row["home_id"] = json!(home);
    // The workbench's v1 record shape resolves local owners as Person IDs,
    // while kernel ownership continues to use authenticated principals.
    row["owner_id"] = json!(visible_person(tx, actor, view.owner_id.as_deref()).await?);
    row["origin"] = state.origin.clone();
    row["communication_origin"] = m::communication_origin(tx, state).await?;
    row["created_at_ms"] = json!(chrono::DateTime::parse_from_rfc3339(
        state.created_at.as_ref().unwrap_or(&created)
    )
    .map(|v| v.timestamp_millis())
    .ok());
    let mut reply_ids = Vec::new();
    if let Some(parent) = &state.reply_to {
        if kernel::read_record_on(tx, actor, parent).await?.is_some() {
            reply_ids.push(parent.clone());
        }
    }
    row["reply_to_ids"] = json!(reply_ids);
    row["record_version"] = json!(format!("rec:{}", view.revision));
    row["mentions"] = mentions_as(tx, actor, state).await?;
    row["mentions_count"] = json!(row["mentions"].as_array().map_or(0, Vec::len));
    if let Some(speaker) = &state.speaker {
        row["speaker"] = speaker.clone();
    }
    Ok(row)
}

async fn inbox_row(
    tx: &mut Transaction<'static, Sqlite>,
    actor: &str,
    id: &str,
    state: &kernel::MessageState,
) -> Result<Value> {
    let mut row = message_row(tx, actor, id, state).await?;
    let a = lane(state, actor, "agent");
    let p = lane(state, actor, "preference");
    let r = lane(state, actor, "routing");
    let person: Option<String> =
        sqlx::query_scalar("SELECT person_id FROM kernel_message_people WHERE principal_id=?")
            .bind(actor)
            .fetch_optional(&mut **tx)
            .await?;
    let addressed = person.is_some_and(|p| state.addressed_to.contains(&p));
    let obligation = if !addressed {
        "none"
    } else {
        match row["message_expectation_state"]["state"].as_str() {
            Some("open") => "open",
            Some("satisfied") => "satisfied",
            _ => "none",
        }
    };
    let obligation = r["obligation_state"].as_str().unwrap_or(obligation);
    row["agent"] =
        json!({"state":a["state"].as_str().unwrap_or("unhandled"),"version":version(&a)});
    row["route"] = json!({"executor":r["executor_route"].as_str().unwrap_or(if obligation=="open" {"human"} else {"unassigned"}),"version":version(&r)});
    row["obligation"] =
        json!({"state":obligation,"expectation_state":row["message_expectation_state"]["state"]});
    row["attention"]["flagged"] = json!(flag(&p, "attention_flag"));
    row["attention"]["muted"] = json!(flag(&p, "muted"));
    row["attention"]["snoozed_until"] = p["snoozed_until"].clone();
    row["delivery"] =
        json!({"candidate_count":kernel::notifications::count_on(tx,actor,id).await?});
    let snoozed = p["snoozed_until"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .is_some_and(|d| d > chrono::Utc::now());
    row["_predicates"] = json!({"snoozed":snoozed});
    Ok(row)
}

/// Per-page memo for the v3 identity pass, so each distinct Person, reply
/// target or Collection id is resolved once per page however many items
/// mention it.
#[derive(Default)]
struct InboxIdentityMemo {
    /// Person id -> slot when readable (full record read, the only place a
    /// name is fetched), `None` when not readable.
    slots: BTreeMap<String, Option<Value>>,
    /// Person id -> may View, from a capability check only (no record load).
    can_view: BTreeMap<String, bool>,
    /// Non-Person record id (reply target, Collection) -> readable.
    readable: BTreeMap<String, bool>,
}

impl InboxIdentityMemo {
    /// The slot for a Person the viewer may see. The viewer's own slot is
    /// always returned, with `name: null` when their own Person is unreadable
    /// to them (hosted applies the same rule).
    async fn slot(
        &mut self,
        tx: &mut Transaction<'static, Sqlite>,
        actor: &str,
        person_id: &str,
        viewer_person: Option<&str>,
    ) -> Result<Option<Value>> {
        // A Person already capability-checked as not viewable needs no record
        // read. (A cached "viewable" still needs the read for the name; the
        // kernel memoizes that check per caller and event heads.)
        if !self.slots.contains_key(person_id)
            && viewer_person != Some(person_id)
            && self.can_view.get(person_id) == Some(&false)
        {
            self.slots.insert(person_id.to_owned(), None);
        }
        if !self.slots.contains_key(person_id) {
            let viewer = viewer_person == Some(person_id);
            let slot = match kernel::read_record_on(tx, actor, person_id).await? {
                Some(record) => Some(json!({
                    "person_id": record.id,
                    "name": record.fields.get("title").and_then(Value::as_str),
                    "viewer": viewer,
                    "state": "person",
                })),
                None if viewer => Some(
                    json!({"person_id": person_id, "name": null, "viewer": true, "state": "person"}),
                ),
                None => None,
            };
            self.can_view.insert(person_id.to_owned(), slot.is_some());
            self.slots.insert(person_id.to_owned(), slot);
        }
        Ok(self.slots[person_id].clone())
    }

    /// Whether the viewer may see this Person, without loading the record.
    async fn person_visible(
        &mut self,
        tx: &mut Transaction<'static, Sqlite>,
        actor: &str,
        person_id: &str,
        viewer_person: Option<&str>,
    ) -> Result<bool> {
        if viewer_person == Some(person_id) {
            return Ok(true);
        }
        if let Some(known) = self.can_view.get(person_id) {
            return Ok(*known);
        }
        let allowed = kernel::kernel_effective_capability_on(tx, actor, person_id)
            .await?
            .allows(Capability::View);
        self.can_view.insert(person_id.to_owned(), allowed);
        Ok(allowed)
    }

    async fn record_readable(
        &mut self,
        tx: &mut Transaction<'static, Sqlite>,
        actor: &str,
        id: &str,
    ) -> Result<bool> {
        if let Some(known) = self.readable.get(id) {
            return Ok(*known);
        }
        // The workspace root is `native:root` on the wire but a separate root
        // anchor in the kernel (`collection_origin` maps it the same way).
        let readable = if id == "native:root" {
            kernel::kernel_effective_capability_on(tx, actor, crate::events::KERNEL_ROOT_ID)
                .await?
                .allows(Capability::View)
        } else {
            kernel::read_record_on(tx, actor, id).await?.is_some()
        };
        self.readable.insert(id.to_owned(), readable);
        Ok(readable)
    }
}

/// `native.message-inbox.v3` identity fields for one page of inbox states,
/// with the hosted semantics (`messaging_inbox_identity.rs`): the sender; the
/// viewer's visible participants only (viewer first, then by Person id, at
/// most the shared cap, `participant_count` = visible total, hidden members
/// omitted); `reply_to_id` only when visible; and a `conversation` that has a
/// key only for a Collection the viewer can see.
///
/// Cost: one capability pass over the union of participant ids across the
/// page (each distinct id once), and a full record read only for ids that are
/// actually listed (at most the cap per item, shared across items).
async fn inbox_identity_page(
    tx: &mut Transaction<'static, Sqlite>,
    actor: &str,
    viewer_person: Option<&str>,
    states: &[kernel::MessageState],
) -> Result<Vec<serde_json::Map<String, Value>>> {
    let mut memo = InboxIdentityMemo::default();
    let mut senders: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut out = Vec::with_capacity(states.len());
    for state in states {
        let mut fields = serde_json::Map::new();
        let sender_person = match state.author.as_deref() {
            Some(author) => {
                if !senders.contains_key(author) {
                    let person: Option<String> = sqlx::query_scalar(
                        "SELECT person_id FROM kernel_message_people WHERE principal_id=?",
                    )
                    .bind(author)
                    .fetch_optional(&mut **tx)
                    .await?;
                    senders.insert(author.to_owned(), person);
                }
                senders[author].clone()
            }
            None => None,
        };
        let sender = match sender_person.as_deref() {
            Some(id) => memo.slot(tx, actor, id, viewer_person).await?,
            None => None,
        };
        let mut sender = sender.unwrap_or_else(crate::awareness::inbox_hidden_person);
        if let (Some(speaker), true) = (&state.speaker, sender["state"] == "person") {
            sender["speaker"] = json!({"kind": speaker["kind"], "assurance": speaker["assurance"]});
        }
        fields.insert("sender".into(), sender);

        let in_unfiled = state
            .home_id
            .as_deref()
            .is_none_or(|home| home == "native:unfiled");
        // Authored by the viewer's own principal (not merely a principal that
        // now resolves to the viewer's Person), in the Unfiled origin.
        let is_self = state.origin["type"] == "collection"
            && state.origin["collection_id"] == "native:unfiled"
            && state.author.as_deref() == Some(actor)
            && in_unfiled
            && state.addressed_to.is_empty()
            && viewer_person.is_some()
            && sender_person.as_deref() == viewer_person;
        let legacy = !matches!(state.origin["type"].as_str(), Some("direct" | "collection"));
        let mut direct_ids: Vec<&str> = if state.origin["type"] == "direct" {
            state.origin["participant_ids"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect()
        } else if legacy {
            // A legacy Message stores no origin members: its audience is the
            // sender plus its addressees.
            state
                .addressed_to
                .iter()
                .map(String::as_str)
                .chain(sender_person.as_deref())
                .collect()
        } else if is_self {
            sender_person.as_deref().into_iter().collect()
        } else {
            Vec::new()
        };
        direct_ids.sort_unstable();
        direct_ids.dedup();
        // Viewer first, then Person-id order: the shared participant order.
        direct_ids.sort_by_key(|id| viewer_person != Some(*id));
        let mut listed = Vec::new();
        let mut visible_count = 0usize;
        for id in &direct_ids {
            if listed.len() < crate::awareness::INBOX_PARTICIPANT_CAP {
                if let Some(slot) = memo.slot(tx, actor, id, viewer_person).await? {
                    visible_count += 1;
                    listed.push(slot);
                }
            } else if memo.person_visible(tx, actor, id, viewer_person).await? {
                visible_count += 1;
            }
        }
        fields.insert("participant_count".into(), json!(visible_count));
        fields.insert(
            "participants".into(),
            Value::Array(crate::awareness::inbox_participants(listed)),
        );

        let reply = match &state.reply_to {
            Some(target) if memo.record_readable(tx, actor, target).await? => json!(target),
            _ => Value::Null,
        };
        fields.insert("reply_to_id".into(), reply);

        // A direct context has no key in this version; a Collection is keyed
        // by its id only for a viewer who can see that Collection.
        let conversation = match state.origin["type"].as_str() {
            _ if is_self => json!({"type": "self"}),
            Some("direct") => json!({"type": "direct"}),
            Some("collection") => {
                let collection = state.origin["collection_id"].as_str().unwrap_or_default();
                if memo.record_readable(tx, actor, collection).await? {
                    json!({"type": "collection", "key": format!("collection:{collection}")})
                } else {
                    json!({"type": "collection"})
                }
            }
            _ => json!({"type": "legacy"}),
        };
        fields.insert("conversation".into(), conversation);
        out.push(fields);
    }
    Ok(out)
}

async fn read(db: &Db, actor: &str, args: Value) -> Result<Value> {
    if args["action"] == "list_notification_candidates" {
        let number = |key: &str, default: i64| -> Result<i64> {
            args.get(key).map_or(Ok(default), |value| {
                value
                    .as_i64()
                    .ok_or_else(|| invalid("candidate cursor and limit must be integers"))
            })
        };
        let after = number("after_seq", 0)?;
        let limit = number("limit", 50)?;
        if after < 0 || !(1..=200).contains(&limit) {
            return Err(invalid(
                "candidate after_seq must be nonnegative; limit must be 1..=200",
            ));
        }
        let mut tx = db.write_pool().begin().await?;
        kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
        let (candidates, scanned) =
            kernel::notifications::rows_on(&mut tx, actor, after, limit).await?;
        let head = kernel::notifications::head_on(&mut tx, actor).await?;
        return Ok(
            json!({"candidates":candidates,"delivery_facts_are_not_awareness":true,"retention_floor":crate::awareness::CANDIDATE_RETENTION_FLOOR,"scanned_through":scanned,"head":head}),
        );
    }
    let action = text(&args, "action")?;
    let mut tx = db.write_pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    if action == "list_destinations" {
        let raw:Vec<(String,String)>=sqlx::query_as("SELECT collection_id,state FROM kernel_message_destinations WHERE principal_id=? ORDER BY json_extract(state,'$.joined_at') DESC,collection_id").bind(actor).fetch_all(&mut *tx).await?;
        let mut destinations = Vec::new();
        for (id, raw) in raw {
            let state: Value = serde_json::from_str(&raw)?;
            if !flag(&state, "present") && args["include_removed"] != true {
                continue;
            }
            match collection_origin(&mut tx, actor, &id).await {
                Ok(()) => (),
                Err(Error::Engine(message))
                    if message == kernel::HIDDEN_OR_MISSING
                        || message.contains("origin must be a Collection") =>
                {
                    continue
                }
                Err(error) => return Err(error),
            }
            destinations.push(json!({"collection_id":id,"present":flag(&state,"present"),"joined_at":state["joined_at"],"joined_by":state["joined_by"],"version":version(&state)}));
        }
        tx.rollback().await?;
        return Ok(json!({"destinations":destinations,"viewer_relative":true}));
    }

    let content = head(&mut tx).await?;
    if action == "list_message_state" {
        let ids = strings(&args["message_ids"])?;
        if ids.is_empty()
            || ids.len() > 200
            || ids.iter().collect::<BTreeSet<_>>().len() != ids.len()
        {
            return Err(invalid("message_ids requires 1..200 unique ids"));
        }
        let mut messages = Vec::new();
        for id in ids {
            let state = require(&mut tx, actor, &id).await?;
            messages.push(state_value(&mut tx, actor, &id, &state).await?);
        }
        tx.rollback().await?;
        return Ok(
            json!({"schema":"native.message-state.v1","content_head":content,"messages":messages,"viewer_relative":true,"snapshot_consistent":true}),
        );
    }
    let conversation = args["conversation_id"].as_str();
    if let Some(id) = conversation {
        kernel::kernel_require(&mut tx, actor, id, Capability::View).await?;
    }
    let origin = if action == "list_context" {
        Some(normalized_origin(&args["origin"])?)
    } else {
        None
    };
    // V1 resolves the request's Person IDs to canonical principals for the
    // response (tools/messaging.rs::resolve_context_selector). Keep the
    // stored selector unchanged for filtering and cursor admission.
    let mut response_origin = origin.clone();
    if let Some(origin) = &origin {
        match text(origin, "type")? {
            "collection" => {
                collection_origin(&mut tx, actor, text(origin, "collection_id")?).await?
            }
            "direct" => {
                let participants = strings(&origin["participant_ids"])?;
                let mut caller_in = false;
                let mut principals = Vec::with_capacity(participants.len());
                for id in &participants {
                    let principal = person(&mut tx, actor, id).await?;
                    caller_in |= principal == actor;
                    principals.push(principal);
                }
                if !caller_in {
                    return Err(invalid("caller must belong to direct context"));
                }
                let principals = crate::events::normalize_direct_origin_principals(principals);
                if principals.len() != participants.len() {
                    return Err(invalid(
                        "direct participants must resolve to distinct canonical principals",
                    ));
                }
                response_origin = Some(serde_json::to_value(
                    crate::events::MessageOriginDeclaredPayload::Direct { principals },
                )?);
            }
            _ => return Err(invalid("invalid origin")),
        }
    }
    let limit = args["limit"]
        .as_u64()
        .unwrap_or(if action == "list_context" { 200 } else { 50 }) as usize;
    if !(1..=200).contains(&limit) {
        return Err(invalid("limit must be 1..200"));
    }
    let limit = if matches!(action, "list_context" | "list_inbox") {
        limit
    } else {
        10_000
    };
    let view = args["view"].as_str().unwrap_or("needs_me");
    // `scope:"direct"` (list_inbox only): the viewer's own direct contexts.
    let direct_scope = match args["scope"].as_str() {
        None if args["scope"].is_null() => false,
        Some("direct") if action == "list_inbox" => true,
        _ => return Err(invalid("inbox scope must be \"direct\"")),
    };
    if direct_scope && conversation.is_some() {
        return Err(invalid(
            "inbox scope and conversation_id are mutually exclusive",
        ));
    }
    let preview_chars = match args.get("preview_chars").filter(|v| !v.is_null()) {
        Some(v) => match v.as_u64() {
            Some(n)
                if (1..=crate::mcp::tools::messaging::MAX_PREVIEW_CHARS as u64).contains(&n) =>
            {
                Some(n as usize)
            }
            _ => return Err(invalid("inbox preview_chars must be 1..=1000")),
        },
        None => {
            direct_scope.then_some(crate::mcp::tools::messaging::DIRECT_SCOPE_DEFAULT_PREVIEW_CHARS)
        }
    };
    if ![
        "needs_me",
        "agent_queue",
        "handled_without_me",
        "all_new",
        "browse",
    ]
    .contains(&view)
    {
        return Err(invalid("invalid inbox view"));
    }
    // Snapshot tokens bind the caller and selection, and every continuation
    // reauthorizes in this snapshot. No retained body is returned after revocation.
    let mut truncated = false;
    let token = args["snapshot"].as_str().or(args["cursor"].as_str());
    let mut after = args["after"].as_u64().unwrap_or(0) as usize;
    let (ids, snapshot_head) = if let Some(token) = token {
        let snapshot = db.get_inbox_snapshot(token)?;
        if snapshot["actor"] != actor
            || snapshot["action"] != action
            || snapshot["origin"] != args["origin"]
            || snapshot["conversation_id"] != args["conversation_id"]
            || snapshot["view"] != args["view"]
            || snapshot["scope"] != args["scope"]
        {
            return Err(invalid("snapshot selection mismatch"));
        }
        if action == "list_context" {
            after = snapshot["after"].as_u64().unwrap_or(0) as usize;
        }
        truncated = snapshot["truncated"].as_bool().unwrap_or(false);
        (
            strings(&snapshot["ids"])?,
            snapshot["head"].as_i64().unwrap_or(0),
        )
    } else {
        let candidates: Vec<String> = if direct_scope {
            let viewer: Option<String> = sqlx::query_scalar(
                "SELECT person_id FROM kernel_message_people WHERE principal_id=?",
            )
            .bind(actor)
            .fetch_optional(&mut *tx)
            .await?;
            let viewer = viewer.ok_or_else(|| {
                invalid("manage_messages.list_inbox: scope direct needs a current member identity")
            })?;
            // One state-JSON scan selects the viewer's contexts (no kernel
            // index covers participants yet, so it is O(messages) but cheap
            // per row; adding one needs a kernel schema migration, tracked as
            // a follow-up). Deleted messages are excluded as on hosted. The
            // per-message work then runs only for these, and visibility is
            // applied BEFORE the cap, newest first, so unreadable messages
            // never use up the cap or set `truncated`: it means more visible
            // direct messages exist. A note to self (the viewer's own collection-origin message in Unfiled with no
            // addressee) is the third arm. (Kernel principals map 1:1 to a Person,
            // and direct origins are Person ids, so there are no aliases.)
            let matched: Vec<String> = sqlx::query_scalar(
                "SELECT m.message_id FROM kernel_messages m JOIN kernel_records r ON r.id=m.message_id
                  WHERE NOT EXISTS (SELECT 1 FROM kernel_import_tombstones t WHERE t.record_id=m.message_id)
                    AND ((json_extract(m.state,'$.origin.type')='direct'
                          AND EXISTS (SELECT 1 FROM json_each(m.state,'$.origin.participant_ids') j WHERE j.value=?1))
                     OR (COALESCE(json_extract(m.state,'$.origin.type'),'') NOT IN ('direct','collection')
                         AND (json_extract(m.state,'$.author')=?2
                              OR EXISTS (SELECT 1 FROM json_each(m.state,'$.addressed_to') a WHERE a.value=?1))
                         AND (json_extract(m.state,'$.home_id') IS NULL
                              OR json_extract(m.state,'$.home_id')='native:unfiled'))
                     OR (json_extract(m.state,'$.origin.type')='collection'
                         AND json_extract(m.state,'$.origin.collection_id')='native:unfiled'
                         AND json_extract(m.state,'$.author')=?2
                         AND json_array_length(COALESCE(json_extract(m.state,'$.addressed_to'),'[]'))=0
                         AND (json_extract(m.state,'$.home_id') IS NULL
                              OR json_extract(m.state,'$.home_id')='native:unfiled')))
                  ORDER BY COALESCE(json_extract(m.state,'$.created_at'),r.created_at) DESC,r.id DESC",
            )
            .bind(&viewer)
            .bind(actor)
            .fetch_all(&mut *tx)
            .await?;
            let cap = crate::mcp::tools::messaging::direct_scope_cap();
            let mut ids = Vec::new();
            for id in matched {
                if kernel::kernel_effective_capability_on(&mut tx, actor, &id)
                    .await?
                    .allows(Capability::View)
                {
                    ids.push(id);
                    if ids.len() > cap {
                        break;
                    }
                }
            }
            truncated = ids.len() > cap;
            ids.truncate(cap);
            ids
        } else {
            sqlx::query_scalar("SELECT m.message_id FROM kernel_messages m JOIN kernel_records r ON r.id=m.message_id ORDER BY COALESCE(json_extract(m.state,'$.created_at'),r.created_at) DESC,r.id DESC").fetch_all(&mut *tx).await?
        };
        let mut ids = Vec::new();
        for id in candidates {
            if !kernel::kernel_effective_capability_on(&mut tx, actor, &id)
                .await?
                .allows(Capability::View)
            {
                continue;
            }
            let state = m::on(&mut tx, &id)
                .await?
                .ok_or_else(|| invalid("message projection missing"))?;
            if origin.as_ref().is_some_and(|o| o != &state.origin)
                || conversation.is_some_and(|c| !state.conversations.iter().any(|s| s == c))
                || (action == "list_unclassified" && !state.conversations.is_empty())
            {
                continue;
            }
            if action == "get_attention" {
                let p = lane(&state, actor, "preference");
                let h = lane(&state, actor, "human");
                let snoozed = p["snoozed_until"]
                    .as_str()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .is_some_and(|d| d > chrono::Utc::now());
                let new = p["unread_override"]
                    .as_bool()
                    .or_else(|| p["unread_override"].as_i64().map(|i| i != 0))
                    .unwrap_or(h["stage"].as_str().unwrap_or("unsurfaced") == "unsurfaced");
                if new
                    && !flag(&p, "muted")
                    && !flag(&p, "archived")
                    && !snoozed
                    && (state.author.as_deref() != Some(actor) || state.speaker.is_some())
                    && (!state.origin.is_null() || state.home_id.is_some())
                {
                    tx.rollback().await?;
                    return Ok(
                        json!({"schema":"native.message-attention.v1","has_new_messages":true,"viewer_relative":true}),
                    );
                }
                continue;
            }
            // A direct-scope browse pins only ids; items are built for the page.
            if action == "list_inbox" && !(direct_scope && view == "browse") {
                let row = inbox_row(&mut tx, actor, &id, &state).await?;
                if !crate::mcp::tools::messaging::item_in_view(&row, view) {
                    continue;
                }
            }
            ids.push(id);
        }
        (ids, content)
    };
    if after > ids.len() {
        return Err(invalid("after exceeds snapshot"));
    }
    let viewer_person: Option<String> = if action == "list_inbox" {
        sqlx::query_scalar("SELECT person_id FROM kernel_message_people WHERE principal_id=?")
            .bind(actor)
            .fetch_optional(&mut *tx)
            .await?
    } else {
        None
    };
    let mut rows = Vec::new();
    let mut page_states: Vec<kernel::MessageState> = Vec::new();
    let mut conversations = BTreeMap::<String, usize>::new();
    let mut offset = after;
    while offset < ids.len() && rows.len() < limit {
        let id = &ids[offset];
        offset += 1;
        if !kernel::kernel_effective_capability_on(&mut tx, actor, id)
            .await?
            .allows(Capability::View)
        {
            continue;
        }
        let state = m::on(&mut tx, id)
            .await?
            .ok_or_else(|| invalid("message projection missing"))?;
        for c in &state.conversations {
            if kernel::read_record_on(&mut tx, actor, c).await?.is_some() {
                *conversations.entry(c.clone()).or_default() += 1;
            }
        }
        let mut row = message_row(&mut tx, actor, id, &state).await?;
        if action == "list_inbox" {
            row = inbox_row(&mut tx, actor, id, &state).await?;
            row.as_object_mut().unwrap().remove("_predicates");
            // Raw origin fields list every participant principal/Person id,
            // hidden ones included; the v3 identity fields replace them.
            let object = row.as_object_mut().unwrap();
            object.remove("origin");
            object.remove("communication_origin");
            page_states.push(state);
        }
        rows.push(row);
    }
    if action == "list_inbox" {
        let identity =
            inbox_identity_page(&mut tx, actor, viewer_person.as_deref(), &page_states).await?;
        for (row, fields) in rows.iter_mut().zip(identity) {
            row.as_object_mut().unwrap().extend(fields);
        }
    }
    let candidate_head = kernel::notifications::head_on(&mut tx, actor).await?;
    tx.rollback().await?;
    let snapshot=db.put_inbox_snapshot(json!({"actor":actor,"action":action,"origin":args["origin"],"conversation_id":args["conversation_id"],"view":args["view"],"scope":args["scope"],"truncated":truncated,"ids":ids,"head":snapshot_head,"after":offset}))?;
    let has_more = offset < ids.len();
    match action {
        "list_context" => Ok(
            json!({"origin":response_origin,"messages":rows,"viewer_relative":true,"has_more":has_more,"next_cursor":if has_more {Some(snapshot)} else {None}}),
        ),
        "list_inbox" => {
            if let Some(limit_chars) = preview_chars {
                for row in &mut rows {
                    crate::mcp::tools::messaging::apply_preview(row, limit_chars);
                }
            }
            let mut response = json!({"schema":crate::awareness::MESSAGE_INBOX_SCHEMA,"view":view,"items":rows,"snapshot":snapshot,"next_after":if has_more {Some(offset)} else {None},"newer_available":content!=snapshot_head,"heads":{"content":content,"awareness":content,"candidates":candidate_head,"control":0,"authorization":content},"counts_are_distinct_message_ids":true});
            if direct_scope {
                response["scope"] = json!("direct");
                response["candidate_cap"] = json!(crate::mcp::tools::messaging::direct_scope_cap());
                response["truncated"] = json!(truncated);
            }
            crate::awareness::validate_messaging_surface_response(&response)?;
            Ok(response)
        }
        "list_my_conversations" => Ok(
            json!({"conversations":conversations.into_iter().map(|(id,count)|json!({"conversation_id":id,"visible_message_count":count})).collect::<Vec<_>>(),"derived_from_readable_messages":true}),
        ),
        "get_attention" => Ok(
            json!({"schema":"native.message-attention.v1","has_new_messages":false,"viewer_relative":true}),
        ),
        _ => Ok(json!({"messages":rows,"viewer_relative":true})),
    }
}

#[cfg(test)]
#[path = "messaging_tests.rs"]
mod tests;

async fn resolve_speaker(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    claim: Option<&Value>,
) -> Result<Option<Value>> {
    let Some(id) = crate::persona::claim_persona_id(claim)? else {
        return Ok(None);
    };
    let not_found = || invalid("speaker not found");
    let persona = m::persona_on(conn, id).await?.ok_or_else(not_found)?;
    let record = kernel::read_record_on(conn, actor, id)
        .await?
        .ok_or_else(not_found)?;
    if persona.owner_principal != actor
        || persona.state != "active"
        || record.owner_id.as_deref() != Some(actor)
        || record.fields.get("v1_type").and_then(Value::as_str) != Some("Entity")
        || record.fields.get("v1_kind").and_then(Value::as_str) != Some("persona")
    {
        return Err(not_found());
    }
    Ok(Some(
        json!({"kind":"persona","id":id,"display_name":record.fields.get("title"),"assurance":"client_asserted"}),
    ))
}

pub(super) async fn mentions_as(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    state: &kernel::MessageState,
) -> Result<Value> {
    let mut rows = Vec::new();
    for mention in &state.mentions {
        let id = mention["target_id"]
            .as_str()
            .or_else(|| mention["target_record_id"].as_str())
            .unwrap_or_default();
        if kernel::read_record_on(conn, actor, id).await?.is_some() {
            let mut row = mention.clone();
            row["target_id"] = json!(id);
            rows.push(row);
        }
    }
    Ok(json!(rows))
}

/// Map the kernel principal to the caller-visible v1 Person identity.
pub(super) async fn visible_person(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    principal: Option<&str>,
) -> Result<Option<String>> {
    let Some(principal) = principal else {
        return Ok(None);
    };
    let person: Option<String> =
        sqlx::query_scalar("SELECT person_id FROM kernel_message_people WHERE principal_id=?")
            .bind(principal)
            .fetch_optional(&mut *tx)
            .await?;
    match person {
        Some(id) => Ok(kernel::read_record_on(tx, actor, &id)
            .await?
            .map(|record| record.id)),
        None => Ok(None),
    }
}

pub(super) async fn participants(db: &Db, actor: &str, args: Value) -> Result<Value> {
    crate::mcp::tools::participants::validate_kernel_arguments(&args)?;
    let action = text(&args, "action")?;
    let mut tx = begin_write(db.write_pool()).await?;
    m::ensure_schema(&mut tx).await?;
    let owner_person: String =
        sqlx::query_scalar("SELECT person_id FROM kernel_message_people WHERE principal_id=?")
            .bind(actor)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| {
                invalid("manage_participants requires one canonical owner Person and principal")
            })?;
    if action == "list" {
        let rows: Vec<(String,String)>=sqlx::query_as("SELECT persona_id,state FROM kernel_personas WHERE json_extract(state,'$.owner_principal')=? ORDER BY persona_id")
            .bind(actor).fetch_all(&mut *tx).await?;
        let mut participants = Vec::new();
        for (id, raw) in rows {
            if let Some(record) = kernel::read_record_on(&mut tx, actor, &id).await? {
                let state: m::PersonaState = serde_json::from_str(&raw)?;
                participants.push(json!({"kind":"persona","persona_id":id,"participant_address":format!("persona:{id}"),"display_name":record.fields.get("title"),"state":state.state}));
            }
        }
        return Ok(json!({"participants":participants}));
    }
    if text(&args, "reason")?.trim().is_empty() {
        return Err(invalid("reason must not be blank"));
    }
    if let Some(key) = args.get("idempotency_key").filter(|v| !v.is_null()) {
        if key
            .as_str()
            .is_none_or(|key| key.trim().is_empty() || key.chars().count() > 200)
        {
            return Err(invalid("idempotency_key must be 1..200 characters"));
        }
    }
    for field in ["name", "body", "record_id", "home_id"] {
        if args[field].as_str().is_some_and(|v| v.trim().is_empty()) {
            return Err(invalid("persona text arguments must not be blank"));
        }
    }
    let request = crate::interventions::sha256_json(&args)?;
    let key = args["idempotency_key"]
        .as_str()
        .map(|key| format!("participants:{key}"));
    if let Some(key) = &key {
        let old:Option<(String,String)>=sqlx::query_as("SELECT request,receipt FROM kernel_message_receipts WHERE principal_id=? AND operation_key=?")
            .bind(actor).bind(key).fetch_optional(&mut *tx).await?;
        if let Some((old, receipt)) = old {
            if old != request {
                return Err(Error::conflict("participant idempotency_key reused"));
            }
            let receipt: Value = serde_json::from_str(&receipt)?;
            kernel::kernel_require(
                &mut tx,
                actor,
                text(&receipt, "persona_id")?,
                Capability::View,
            )
            .await?;
            return Ok(receipt);
        }
    }
    let mut acts = ActAllocation::new();
    let (id, state) = if action == "register_persona" {
        let id = if let Some(id) = args["record_id"].as_str() {
            if ["name", "body", "home_id"]
                .iter()
                .any(|key| args.get(key).is_some_and(|v| !v.is_null()))
            {
                return Err(invalid("edit an existing profile with update_record"));
            }
            let profile = kernel::read_record_on(&mut tx, actor, id)
                .await?
                .ok_or_else(|| invalid("owned persona not found"))?;
            if profile.owner_id.as_deref() != Some(actor)
                || profile.fields.get("v1_type").and_then(Value::as_str) != Some("Entity")
                || profile.fields.get("v1_kind").and_then(Value::as_str) != Some("persona")
            {
                return Err(invalid(
                    "register_persona requires an owned Entity/persona profile",
                ));
            }
            let root = kernel::kernel_policy_anchor_on(&mut tx, &profile.home_id).await?;
            let foreign:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_policy_entries WHERE root_id=? AND (subject_kind!='account' OR subject_id!=? OR effect!='allow'))")
                .bind(root).bind(actor).fetch_one(&mut *tx).await?;
            if foreign {
                return Err(invalid(
                    "existing persona profile must already be owner-only",
                ));
            }
            if let Some(facets) = args.get("facets").filter(|v| !v.is_null()) {
                super::writes::update(
                    db,
                    &mut tx,
                    &mut acts,
                    actor,
                    &json!({"id":id,"facets":facets,"reason":args["reason"]}),
                )
                .await?;
            }
            id.to_owned()
        } else {
            if text(&args, "name")?.trim().is_empty() {
                return Err(invalid("persona name must not be blank"));
            }
            let parent = if let Some(home) = args["home_id"].as_str() {
                crate::v1_import::resolve_home_on(&mut tx, actor, home).await?
            } else {
                crate::events::KERNEL_ROOT_ID.into()
            };
            kernel::kernel_require(&mut tx, actor, &parent, Capability::Edit).await?;
            let home = uuid::Uuid::new_v4().to_string();
            append(db,&mut tx,&mut acts,actor,&home,kernel::KERNEL_HOME_CREATED_EVENT,json!({"parent_id":parent,"owner_id":actor,"entries":[{"subject_id":actor,"capability":"manage"}]})).await?;
            let mut create = json!({"type":"Entity","kind":"persona","name":args["name"],"home_id":home,"reason":args["reason"]});
            for key in ["body", "facets"] {
                if let Some(value) = args.get(key).filter(|v| !v.is_null()) {
                    create[key] = value.clone();
                }
            }
            let receipt =
                super::writes::create_with_message(db, &mut tx, &mut acts, actor, &create, None)
                    .await?;
            text(&receipt, "id")?.to_owned()
        };
        if m::persona_on(&mut tx, &id).await?.is_some() {
            return Err(invalid("persona identity is already registered"));
        }
        (
            id,
            m::PersonaState {
                owner_principal: actor.into(),
                owner_person_id: owner_person,
                state: "active".into(),
                source: None,
            },
        )
    } else {
        let id = text(&args, "persona_id")?;
        kernel::kernel_require(&mut tx, actor, id, Capability::View).await?;
        let mut state = m::persona_on(&mut tx, id)
            .await?
            .ok_or_else(|| invalid("persona does not exist or is not active"))?;
        if state.owner_principal != actor || state.state != "active" {
            return Err(invalid("persona does not exist or is not active"));
        }
        state.state = "retired".into();
        (id.into(), state)
    };
    append(
        db,
        &mut tx,
        &mut acts,
        actor,
        &id,
        if action == "register_persona" {
            m::PERSONA
        } else {
            m::RETIRE_PERSONA
        },
        serde_json::to_value(&state)?,
    )
    .await?;
    let receipt = json!({"id":id,"persona_id":id,"participant_address":format!("persona:{id}"),"state":state.state,"act":acts.get()});
    if let Some(key) = key {
        append(
            db,
            &mut tx,
            &mut acts,
            actor,
            actor,
            m::COMMAND,
            serde_json::to_value(m::CommandReceipt {
                operation_key: key,
                request,
                receipt: receipt.clone(),
                nonce: None,
            })?,
        )
        .await?;
    }
    tx.commit().await?;
    if let Some(hub) = db.realtime_hub() {
        hub.wake();
    }
    Ok(receipt)
}

/// v1: tools/messaging.rs:2331 (mark), :2544 (unmark), :1648 (own live marks).
/// View of a local Message is sufficient; neither home Edit nor sender identity
/// is required. Caller-owned evidence derives live authority from the Message.
async fn relevance(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut ActAllocation,
    actor: &str,
    args: &Value,
) -> Result<Value> {
    let message = text(args, "message_id")?;
    require(tx, actor, message).await?;
    let bound: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_message_people WHERE principal_id=?)",
    )
    .bind(actor)
    .fetch_one(&mut **tx)
    .await?;
    if !bound {
        return Err(invalid("marking requires a portable account binding"));
    }
    let existing = m::own_relevance_marks_on(tx, actor, message).await?;
    if args["action"] == "unmark_no_longer_relevant" {
        for (id, link) in &existing {
            append(
                db,
                tx,
                acts,
                actor,
                id,
                "kernel.generic_link_removed.v1",
                json!({"link_id":link}),
            )
            .await?;
        }
        return Ok(
            json!({"status":"unmarked","message_id":message,"changed":!existing.is_empty()}),
        );
    }
    if let Some((id, link)) = existing.first() {
        // v1 re-appends the live link under a new key even when changed=false.
        // This also makes the owner the latest asserting actor of a link that
        // somebody else with Edit may originally have put on their evidence.
        append(
            db,
            tx,
            acts,
            actor,
            id,
            "kernel.generic_link_added.v1",
            json!({"link_id":link,"source_id":id,"target_id":message,"relationship":"resolves","note":"no_longer_relevant"}),
        )
        .await?;
        return Ok(
            json!({"status":"marked","message_id":message,"evidence_record_id":id,"changed":false}),
        );
    }
    let source = kernel::read_record_on(tx, actor, message)
        .await?
        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    let fields = crate::v2_standard::v1_compat::compat_fields(
        "Annotation",
        "no_longer_relevant",
        Some("No longer relevant"),
        None,
        None,
    );
    let raw = serde_json::to_string(&fields)?;
    let id = kernel::create_input_admitted_in(
        db,
        tx,
        acts,
        actor,
        crate::v2_standard::v1_compat::FAMILY,
        crate::v2_standard::v1_compat::KIND,
        kernel::FieldInput::Raw(&raw),
        &source.home_id,
        None,
        false,
        None,
        None,
        None,
    )
    .await?;
    append(
        db,
        tx,
        acts,
        actor,
        &id,
        "kernel.body_set.v1",
        json!({"body":args["note"].as_str().unwrap_or("")}),
    )
    .await?;
    // All Annotations derive authority from their unique part_of bearer on
    // both engines (v1 authorization.rs:1292). Complete that bearer last, so
    // body and relevance writes share the owned creation fence. The sealed
    // owner-only relevance route admits later reaffirm/undo with Message View.
    append(db, tx, acts, actor, &id, "kernel.generic_link_added.v1",
        json!({"link_id":uuid::Uuid::new_v4().to_string(),"source_id":id,"target_id":message,"relationship":"resolves","note":"no_longer_relevant"})).await?;
    kernel::generic_links::add_generic_link_in(db, tx, acts, actor, &id, message, "part_of", None)
        .await?;
    Ok(json!({"status":"marked","message_id":message,"evidence_record_id":id,"changed":true}))
}
