//! Ordinary messaging executor operations over kernel-owned authority and state.
use super::*;
use crate::{
    act::ActAllocation,
    authorization::Capability,
    db::begin_write,
    store::{append_in, AppendSpec},
};
use kernel::messaging as m;
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
    append_in(
        db,
        tx,
        AppendSpec {
            record_id: id.into(),
            event_type: kind.into(),
            payload: value,
            actor: Some(actor.into()),
        },
        acts,
    )
    .await?;
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
    if matches!(
        action,
        "share_history" | "mark_no_longer_relevant" | "unmark_no_longer_relevant"
    ) {
        return Err(unsupported(
            "manage_messages",
            "history sharing, relevance marks and live notification delivery",
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
    let request = crate::interventions::sha256_json(&args)?;
    let mut tx = begin_write(db.write_pool()).await?;
    m::ensure_schema(&mut tx).await?;
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
        } else {
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
    let mut receipt = if action == "send" {
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
    if receipt["changed"] != false && action != "send" {
        let (seq, event_id, act, record_id): (i64, String, Option<i64>, String) = sqlx::query_as(
            "SELECT seq,id,act,record_id FROM main.content_events ORDER BY seq DESC LIMIT 1",
        )
        .fetch_one(&mut *tx)
        .await?;
        receipt["act"] = json!(act);
        receipt["write_receipt"] = json!({"kind":"kernel_content_event","event":{"seq":seq,"event_id":event_id,"record_id":record_id}});
    }
    let unchanged_awareness = action == "mutate_human_awareness" && receipt["changed"] == false;
    if !key.is_empty() && !unchanged_awareness {
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
    tx.commit().await?;
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
                if !addressed.contains(&mention.target_id) {
                    return Err(invalid(
                        "principal mention target must already be addressed",
                    ));
                }
                format!("native/{}", person(tx, actor, &mention.target_id).await?)
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
async fn governed_work_evidence(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    id: &str,
    expectation: &str,
    rules: &kernel::MessageRules,
) -> Result<Option<Value>> {
    let account: Option<String> =
        sqlx::query_scalar("SELECT auth_binding FROM kernel_principals WHERE principal_id=?")
            .bind(actor)
            .fetch_optional(&mut *conn)
            .await?;
    let legacy_actor = account.as_ref().map(|a| format!("v1:{a}"));
    let candidates:Vec<(String,Option<String>)>=sqlx::query_as("SELECT l.source_id,l.actor FROM kernel_generic_links l JOIN kernel_records r ON r.id=l.source_id WHERE l.target_id=? AND l.relationship='derived_from' AND l.active=1 ORDER BY COALESCE((SELECT json_extract(e.payload,'$.legacy.payload.created_at') FROM main.content_events e WHERE e.record_id=r.id AND e.type='kernel.legacy_recorded.v1' AND json_extract(e.payload,'$.legacy.event_type')='v1.snapshot_provenance' ORDER BY e.seq DESC LIMIT 1),r.created_at),r.id").bind(id).fetch_all(&mut *conn).await?;
    for (candidate, link_actor) in candidates {
        if link_actor.as_deref() != Some(actor) && link_actor.as_ref() != legacy_actor.as_ref() {
            continue;
        }
        let Some(view) = kernel::read_record_on(conn, actor, &candidate).await? else {
            continue;
        };
        let (typ, kind) = super::v1_type_and_kind(
            view.family.as_deref(),
            view.pin.as_ref().map(|p| p.version),
            None,
            view.kind.as_deref(),
            &view.fields,
        );
        if (expectation == "action" && typ != Some("WorkItem"))
            || (expectation == "decision" && typ != Some("Resolution"))
        {
            continue;
        }
        let provenance:Option<String>=sqlx::query_scalar("SELECT json_extract(payload,'$.legacy.payload') FROM main.content_events WHERE record_id=? AND type='kernel.legacy_recorded.v1' AND json_extract(payload,'$.legacy.event_type')='v1.snapshot_provenance' ORDER BY seq DESC LIMIT 1").bind(&candidate).fetch_optional(&mut *conn).await?;
        let provenance: Option<Value> = provenance
            .map(|raw| serde_json::from_str(&raw))
            .transpose()?;
        let authored = if let Some(provenance) = &provenance {
            account.as_ref().is_some_and(|account| {
                provenance["creator"] == account.as_str()
                    || provenance["verified_owner_accounts"]
                        .as_array()
                        .is_some_and(|owners| owners.iter().any(|owner| owner == account))
            })
        } else {
            view.owner_id.as_deref()==Some(actor) || sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE record_id=? AND type='kernel.record_created.v1' AND actor=?)").bind(&candidate).bind(actor).fetch_one(&mut *conn).await?
        };
        if !authored {
            continue;
        }
        if expectation == "decision" {
            if kind.is_some_and(|k| rules.decision_kinds.contains(k)) {
                return Ok(Some(json!({"kind":"decision","record_id":candidate})));
            }
            continue;
        }
        let Some(lifecycle) = view.fields.get("lifecycle").and_then(Value::as_str) else {
            continue;
        };
        let home = if let Some(provenance) = &provenance {
            provenance["original_home"].as_str().map(str::to_owned)
        } else if view.home_id == crate::events::KERNEL_ROOT_ID {
            Some("native:root".into())
        } else {
            sqlx::query_scalar("SELECT json_extract(payload,'$.source_record_id') FROM main.content_events WHERE record_id=? AND type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(payload,'$.source_record_id') IS NOT NULL ORDER BY seq LIMIT 1").bind(&view.home_id).fetch_optional(&mut *conn).await?.or(Some(view.home_id.clone()))
        };
        let rows: Vec<crate::query::cascade::SchemaConfigRow> = rules
            .schemas
            .iter()
            .map(|row| crate::query::cascade::SchemaConfigRow {
                id: row["id"].as_str().unwrap_or("").into(),
                layer: row["layer"].as_str().unwrap_or("").into(),
                name: None,
                data: row["data"].clone(),
                applies_to_collection_id: row["applies_to_collection_id"]
                    .as_str()
                    .map(str::to_owned),
                version_lineage: None,
                created_at: row["created_at"].as_str().unwrap_or("").into(),
            })
            .collect();
        let facets = crate::query::cascade::facets_for_record_context(
            &rows,
            "WorkItem",
            kind,
            home.as_deref(),
        );
        let governing = facets
            .get("lifecycle")
            .and_then(|shape| shape.get("vocab").or_else(|| shape.get("vocab_ref")))
            .and_then(Value::as_str)
            .map(crate::meta::resolve_vocab_ref);
        if governing.is_some_and(|g| {
            rules
                .positive
                .get(g)
                .is_some_and(|values| values.contains(lifecycle))
        }) {
            return Ok(Some(
                json!({"kind":"completed_work_item","record_id":candidate}),
            ));
        }
    }
    Ok(None)
}

pub(super) async fn expectation_value(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    id: &str,
    state: &kernel::MessageState,
) -> Result<Value> {
    let declared = state
        .expectation
        .as_deref()
        .filter(|e| crate::message_expectation::EXPECTATION_VALUES.contains(e));
    let mut result = json!({"format":crate::message_expectation::EXPECTATION_DERIVATION_VERSION,"message_id":id,"recipient_id":actor,"expectation":declared,"state":match declared {None=>"unknown",Some("none")=>"not_required",_=>"open"}});
    if matches!(declared, None | Some("none")) {
        return Ok(result);
    }
    if let Some(imported) = state.expectations.get(actor) {
        result = imported.clone();
        result["recipient_id"] = json!(actor);
        if let Some(evidence) = result["evidence"]["record_id"].as_str() {
            if kernel::read_record_on(tx, actor, evidence).await?.is_none() {
                // Retain the source evaluator's satisfaction fact without
                // disclosing an evidence identity hidden on the kernel.
                result.as_object_mut().unwrap().remove("evidence");
            }
        }
    }
    if let (Some(expectation @ ("action" | "decision")), Some(rules)) =
        (declared, state.rules.as_ref())
    {
        // Reconcile current kernel evidence on each read. Reopening a task or
        // deleting evidence cannot leave a stale imported satisfaction flag.
        result["state"] = json!("open");
        result.as_object_mut().unwrap().remove("evidence");
        if let Some(evidence) = governed_work_evidence(tx, actor, id, expectation, rules).await? {
            result["state"] = json!("satisfied");
            result["evidence"] = evidence;
        }
    }
    if declared == Some("ack") && state.acknowledgements.contains_key(actor) {
        result["state"] = json!("satisfied");
        result["evidence"] = json!({"kind":"acknowledgement","record_id":id});
        return Ok(result);
    }
    if matches!(declared, Some("ack" | "reply")) {
        let replies:Vec<(String,String)>=sqlx::query_as("SELECT message_id,state FROM kernel_messages WHERE json_extract(state,'$.reply_to')=? AND json_extract(state,'$.author')=? ORDER BY event_seq,message_id").bind(id).bind(actor).fetch_all(&mut *tx).await?;
        for (reply, raw) in replies {
            let reply_state: kernel::MessageState = serde_json::from_str(&raw)?;
            let sender_person: Option<String> = sqlx::query_scalar(
                "SELECT person_id FROM kernel_message_people WHERE principal_id=?",
            )
            .bind(state.author.as_deref().unwrap_or(""))
            .fetch_optional(&mut *tx)
            .await?;
            let account: String = sqlx::query_scalar(
                "SELECT auth_binding FROM kernel_principals WHERE principal_id=?",
            )
            .bind(actor)
            .fetch_one(&mut *tx)
            .await?;
            let authored:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_generic_links WHERE source_id=? AND target_id=? AND relationship='reply_to' AND active=1 AND actor IN (?,?))").bind(&reply).bind(id).bind(actor).bind(format!("v1:{account}")).fetch_one(&mut *tx).await?;
            // v1 also delivers replies to persona/agent utterances through
            // an explicit reply_to in the same declared Collection.
            let delivered = sender_person.is_some_and(|p| reply_state.addressed_to.contains(&p))
                || (state.speaker.is_some()
                    && state.origin["type"] == "collection"
                    && reply_state.origin == state.origin);
            if authored
                && reply_state.speaker.is_none()
                && delivered
                && kernel::read_record_on(tx, actor, &reply).await?.is_some()
            {
                result["state"] = json!("satisfied");
                result["evidence"] = json!({"kind":"reply","record_id":reply});
                break;
            }
        }
    }
    Ok(result)
}

pub(super) async fn state_value(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    id: &str,
    state: &kernel::MessageState,
) -> Result<Value> {
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
    let mentioned = recipient.as_ref().is_some_and(|p| {
        state.mentions.iter().any(|m| {
            flag(m, "effective")
                && m["target_kind"] == "principal"
                && (m["target_id"] == *p || m["target_record_id"] == *p)
        })
    });
    Ok(
        json!({"message_id":id,"human":{"stage":stage,"version":version(&human)},"mention":{"principal":mentioned},
        "attention":{"unread":unread,"unread_override":unread_override,"version":version(&preference),"archived":flag(&preference,"archived")},"reactions":reactions,
        "message_expectation_state":expectation,"can_satisfy_acknowledgement":can_ack}),
    )
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
    row["owner_id"] = json!(view.owner_id);
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
        let (candidates, scanned) =
            kernel::notifications::rows_on(&mut tx, actor, after, limit).await?;
        let head = kernel::notifications::head_on(&mut tx, actor).await?;
        return Ok(
            json!({"candidates":candidates,"delivery_facts_are_not_awareness":true,"retention_floor":crate::awareness::CANDIDATE_RETENTION_FLOOR,"scanned_through":scanned,"head":head}),
        );
    }
    let action = text(&args, "action")?;
    let mut tx = db.write_pool().begin().await?;
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
    if let Some(origin) = &origin {
        match text(origin, "type")? {
            "collection" => {
                collection_origin(&mut tx, actor, text(origin, "collection_id")?).await?
            }
            "direct" => {
                let participants = strings(&origin["participant_ids"])?;
                let mut caller_in = false;
                for id in participants {
                    caller_in |= person(&mut tx, actor, &id).await? == actor;
                }
                if !caller_in {
                    return Err(invalid("caller must belong to direct context"));
                }
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
    let token = args["snapshot"].as_str().or(args["cursor"].as_str());
    let mut after = args["after"].as_u64().unwrap_or(0) as usize;
    let (ids, snapshot_head) = if let Some(token) = token {
        let snapshot = db.get_inbox_snapshot(token)?;
        if snapshot["actor"] != actor
            || snapshot["action"] != action
            || snapshot["origin"] != args["origin"]
            || snapshot["conversation_id"] != args["conversation_id"]
            || snapshot["view"] != args["view"]
        {
            return Err(invalid("snapshot selection mismatch"));
        }
        if action == "list_context" {
            after = snapshot["after"].as_u64().unwrap_or(0) as usize;
        }
        (
            strings(&snapshot["ids"])?,
            snapshot["head"].as_i64().unwrap_or(0),
        )
    } else {
        let candidates:Vec<String>=sqlx::query_scalar("SELECT m.message_id FROM kernel_messages m JOIN kernel_records r ON r.id=m.message_id ORDER BY COALESCE(json_extract(m.state,'$.created_at'),r.created_at) DESC,r.id DESC").fetch_all(&mut *tx).await?;
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
            if action == "list_inbox" {
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
    let mut rows = Vec::new();
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
        }
        rows.push(row);
    }
    let candidate_head = kernel::notifications::head_on(&mut tx, actor).await?;
    tx.rollback().await?;
    let snapshot=db.put_inbox_snapshot(json!({"actor":actor,"action":action,"origin":args["origin"],"conversation_id":args["conversation_id"],"view":args["view"],"ids":ids,"head":snapshot_head,"after":offset}))?;
    let has_more = offset < ids.len();
    match action {
        "list_context" => Ok(
            json!({"origin":origin,"messages":rows,"viewer_relative":true,"has_more":has_more,"next_cursor":if has_more {Some(snapshot)} else {None}}),
        ),
        "list_inbox" => {
            let response = json!({"schema":crate::awareness::MESSAGE_INBOX_SCHEMA,"view":view,"items":rows,"snapshot":snapshot,"next_after":if has_more {Some(offset)} else {None},"newer_available":content!=snapshot_head,"heads":{"content":content,"awareness":content,"candidates":candidate_head,"control":0,"authorization":content},"counts_are_distinct_message_ids":true});
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
