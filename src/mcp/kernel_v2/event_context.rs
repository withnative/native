//! Event-local context with kernel history disclosure, not current-state guesses.
//! V1 contract: tools/event_context.rs:130-272,285-317,593-698.
use super::*;
use crate::mcp::tools::event_context as v1;
use sqlx::SqliteConnection;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    event_id: String,
}
fn missing(id: &str) -> Error {
    Error::engine(format!("get_event_context: event {id} does not exist"))
}

/// Native schemas are not a v1 payload. Only the mapped ordinary field/body
/// events have a v1 interpretation. Keep opaque provider outcomes unavailable.
fn logical_payload(typ: &str, payload: &Value) -> Option<(String, Value)> {
    if typ == "kernel.legacy_recorded.v1" {
        let typ = payload["legacy"]["event_type"].as_str()?;
        if !matches!(
            typ,
            "record.created"
                | "record.updated"
                | "record.type_corrected.v1"
                | "facet.set"
                | "facet.unset"
                | "link.added"
                | "link.removed"
        ) {
            return None;
        }
        return Some((typ.to_owned(), payload["legacy"]["payload"].clone()));
    }
    let mut fields = payload.get("fields").cloned().unwrap_or_else(|| json!({}));
    if let Some(object) = fields.as_object_mut() {
        for (from, to) in [("title", "name"), ("v1_type", "type"), ("v1_kind", "kind")] {
            if let Some(value) = object.remove(from) {
                object.insert(to.into(), value);
            }
        }
    }
    match typ {
        "kernel.record_created.v1" | "kernel.record_created.v2" => {
            Some(("record.created".into(), fields))
        }
        "kernel.record_revised.v1" | "kernel.record_revised.v2" => {
            Some(("record.updated".into(), fields))
        }
        "kernel.body_set.v1" => Some(("record.updated".into(), json!({"body":payload["body"]}))),
        "kernel.metadata_set.v1" | "kernel.archive_changed.v1" => {
            Some(("record.updated".into(), payload.clone()))
        }
        _ => None,
    }
}
async fn disclosed(
    conn: &mut SqliteConnection,
    actor: &str,
    record: &str,
    seq: i64,
) -> Result<Option<kernel::KernelHistoryEvent>> {
    if kernel::read_record_on(conn, actor, record).await?.is_none() {
        return Ok(None);
    }
    Ok(kernel::history_page_in_range_on(
        conn,
        actor,
        record,
        Some(seq - 1),
        false,
        1,
        true,
        false,
        (seq, seq),
    )
    .await?
    .into_iter()
    .next())
}

pub(super) async fn shaped(
    conn: &mut SqliteConnection,
    actor: &str,
    disclosed: kernel::KernelHistoryEvent,
) -> Result<Value> {
    let row=sqlx::query("SELECT *, (SELECT json_group_array(parent_event_id) FROM content_event_causal_frontier WHERE event_id=content_events.id) AS causal_frontier FROM content_events WHERE id=?")
        .bind(&disclosed.id).fetch_one(&mut *conn).await?;
    let mut event = crate::query::events::event_from_row(&row)?;
    let raw: Value = event
        .payload
        .as_deref()
        .map(serde_json::from_str)
        .transpose()?
        .unwrap_or(Value::Null);
    let canonical = logical_payload(&event.event_type, &raw);
    event.actor = disclosed.actor;
    event.run_key = disclosed.run_key;
    if event.run_key.is_none() {
        event.parent_key = None;
        event.intent = None;
    } else if event.event_type == "kernel.legacy_recorded.v1" {
        event.intent = raw
            .pointer("/legacy/source/metadata/intent")
            .and_then(Value::as_str)
            .map(str::to_owned);
    }
    let canonical = if event.event_type == "kernel.legacy_recorded.v1" {
        disclosed.retained_legacy.as_ref().and_then(|legacy| {
            legacy.get("payload").map(|payload| {
                (
                    legacy["event_type"]
                        .as_str()
                        .unwrap_or("retained_provenance")
                        .to_owned(),
                    payload.clone(),
                )
            })
        })
    } else {
        canonical
    };
    if let Some((typ, payload)) = canonical {
        let mut legacy = json!({"event_type":typ,"payload":payload});
        kernel::legacy_history::redact(
            conn,
            actor,
            &mut legacy,
            false,
            &mut std::collections::BTreeMap::new(),
        )
        .await?;
        scrub_basis(conn, actor, &mut legacy["payload"]).await?;
        event.event_type = typ;
        event.payload = Some(legacy["payload"].to_string());
    } else {
        event.event_type = disclosed
            .retained_legacy
            .as_ref()
            .and_then(|legacy| legacy["event_type"].as_str())
            .unwrap_or_else(|| logical_event_type(&event.event_type))
            .to_owned();
        event.payload = None;
    }
    let names = event
        .actor
        .as_ref()
        .zip(disclosed.actor_name)
        .map(|(id, name)| (id.clone(), name))
        .into_iter()
        .collect();
    let mut value = crate::mcp::tools::history::event_to_value(&event, &names);
    // Generic kernel history does not disclose a frontier or parent lineage.
    // Do not recover unrelated event/run identities from the raw stored row.
    value["causal_envelope"] = Value::Null;
    value["parent_key"] = Value::Null;
    Ok(value)
}

async fn scrub_basis(conn: &mut SqliteConnection, actor: &str, payload: &mut Value) -> Result<()> {
    let Some(entries) = payload.pointer("/basis/sources").and_then(Value::as_array) else {
        return Ok(());
    };
    let mut kept = Vec::new();
    for entry in entries {
        if let Some(id) = entry["record_id"].as_str() {
            if kernel::read_record_on(conn, actor, id).await?.is_some() {
                kept.push(entry.clone());
            }
        }
    }
    payload["basis"]["sources"] = json!(kept);
    Ok(())
}
async fn basis(
    conn: &mut SqliteConnection,
    actor: &str,
    target: &str,
    payload: &Value,
) -> Result<Value> {
    let mut out =
        json!({"label":"Sources","status":"not_declared","completeness":"complete","sources":[]});
    let Some(envelope) = payload
        .get("basis")
        .filter(|b| b["format"] == "native.source-basis.v1")
    else {
        return Ok(out);
    };
    out["status"] = json!("declared");
    let Some(entries) = envelope["sources"].as_array() else {
        out["completeness"] = json!("partial");
        return Ok(out);
    };
    if entries.is_empty() {
        out["status"] = json!("declared_none");
        return Ok(out);
    }
    let mut sources = Vec::new();
    for entry in entries {
        let Some(id) = entry["record_id"].as_str() else {
            out["completeness"] = json!("partial");
            continue;
        };
        let Some(record) = kernel::read_record_on(conn, actor, id).await? else {
            out["completeness"] = json!("partial");
            continue;
        };
        let primary: Option<String> =
            sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
                .bind(id)
                .fetch_one(&mut *conn)
                .await?;
        let (typ, kind) = v1_type_and_kind(
            record.family.as_deref(),
            record.pin.as_ref().map(|p| p.version),
            primary.as_deref(),
            record.kind.as_deref(),
            &record.fields,
        );
        let text = |key: &str| entry[key].as_str().map(str::to_owned);
        sources.push(json!({"record_id":id,"name":record.fields.get("title").or_else(||record.fields.get("name")),"type":typ,"kind":kind,
            "revision_event_id":text("revision_event_id"),"revision_supplied_by":text("revision_supplied_by"),"role":text("role"),"reason":text("reason"),"is_event_target":id==target}));
    }
    out["sources"] = json!(sources);
    Ok(out)
}
async fn body_pair(
    conn: &mut SqliteConnection,
    actor: &str,
    record: &str,
    seq: i64,
) -> Result<(Option<String>, Option<String>)> {
    let before = kernel::historical::body_at_on(conn, actor, record, seq - 1).await?;
    let after = kernel::historical::body_at_on(conn, actor, record, seq).await?;
    Ok((before, after))
}
fn native_body_event(native: &str, raw: &Value) -> bool {
    matches!(
        native,
        "kernel.record_created.v1"
            | "kernel.record_created.v2"
            | "kernel.import_record_created.v1"
            | "kernel.body_set.v1"
            | "kernel.import_state.v1"
            | "kernel.import_state_delta.v1"
    ) || matches!(
        native,
        "kernel.record_revised.v1" | "kernel.record_revised.v2"
    ) && raw["fields"].get("body").is_some()
}
async fn body_delta(
    conn: &mut SqliteConnection,
    actor: &str,
    record: &str,
    seq: i64,
    native: &str,
    raw: &Value,
) -> Result<Value> {
    if native == "kernel.legacy_recorded.v1" {
        return Ok(
            json!({"kind":"unavailable","reason":"retained_source_body_history_unavailable"}),
        );
    }
    if !native_body_event(native, raw) {
        return Ok(json!({"kind":"not_a_body_revision","event_type":logical_event_type(native)}));
    }
    let rows:Vec<(String,i64,String,String)>=sqlx::query_as("SELECT id,seq,type,payload FROM content_events WHERE record_id=? AND seq<? AND type!='kernel.legacy_recorded.v1' ORDER BY seq DESC")
        .bind(record).bind(seq).fetch_all(&mut *conn).await?;
    let mut previous = None;
    let mut is_creation = true;
    for (id, previous_seq, typ, raw) in rows {
        if native_body_event(&typ, &serde_json::from_str(&raw)?) {
            is_creation = false;
            // Current record View alone does not disclose an event identity.
            // Apply the same history oracle used for the selected event.
            if disclosed(conn, actor, record, previous_seq)
                .await?
                .is_some_and(|event| event.id == id)
            {
                previous = Some(id);
            }
            break;
        }
    }
    let (before, after) = body_pair(conn, actor, record, seq).await?;
    Ok(
        json!({"kind":"body_revision","record_id":record,"before_event_id":previous,"before":before,"after":after,"is_creation":is_creation}),
    )
}

pub(super) async fn get(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let args: Args = parse("get_event_context", args)?;
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    let raw: Option<(String, i64, String, String)> =
        sqlx::query_as("SELECT record_id,seq,type,payload FROM content_events WHERE id=?")
            .bind(&args.event_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((record, seq, native, raw)) = raw else {
        return Err(missing(&args.event_id));
    };
    let Some(selected) = disclosed(&mut tx, actor, &record, seq).await? else {
        return Err(missing(&args.event_id));
    };
    if selected.id != args.event_id {
        return Err(missing(&args.event_id));
    }
    let raw: Value = serde_json::from_str(&raw)?;
    // A retained envelope may be disclosed only as a metadata marker. Never
    // recover source-basis prose from raw storage when the history gate
    // withheld it; use exactly the released, already-redacted envelope.
    let canonical = if native == "kernel.legacy_recorded.v1" {
        selected
            .retained_legacy
            .as_ref()
            .filter(|legacy| legacy.get("payload").is_some())
            .and_then(|legacy| logical_payload(&native, &json!({"legacy":legacy})))
    } else {
        logical_payload(&native, &raw)
    };
    let delta = body_delta(&mut tx, actor, &record, seq, &native, &raw).await?;
    let canonical_payload = canonical.as_ref().map(|(_, p)| p).unwrap_or(&Value::Null);
    let mut basis = basis(&mut tx, actor, &record, canonical_payload).await?;
    if native == "kernel.legacy_recorded.v1" && canonical.is_none() {
        basis["completeness"] = json!("partial");
    }
    let key = selected.run_key.clone();
    let event = shaped(&mut tx, actor, selected).await?;
    let intent = event["intent"].clone();
    let mut neighbours = Vec::new();
    if let Some(key) = &key {
        let candidates:Vec<(String,i64)>=sqlx::query_as("SELECT record_id,seq FROM content_events WHERE run_key=? AND id<>? AND seq BETWEEN ? AND ? ORDER BY seq")
            .bind(key).bind(&args.event_id).bind(seq-v1::NEIGHBOUR_WINDOW).bind(seq+v1::NEIGHBOUR_WINDOW).fetch_all(&mut *tx).await?;
        for (id, position) in candidates {
            if let Some(item) = disclosed(&mut tx, actor, &id, position).await? {
                neighbours.push(shaped(&mut tx, actor, item).await?);
            }
        }
    }
    let run=key.map(|key|json!({"agent_key":crate::runkey::agent_key_of(&key),"run_key":key,"assurance":"correlation_only"}));
    tx.rollback().await?;
    Ok(
        json!({"event":event,"run":run,"intent_at_event":intent,"delta":delta,"neighbouring_events":neighbours,
        "consulted":{"label":"Opened before this event","status":"unavailable","records":[],"other_records_surfaced":0,"limit":v1::MAX_CONSULTED},"basis":basis,
        "interpretation_limits":[v1::LIMIT_OPENED_NOT_COMPREHENSION,v1::LIMIT_CONSULTED_BOUNDED,v1::LIMIT_CONSULTED_FILTERED,v1::LIMIT_READ_LOG_BEST_EFFORT,v1::LIMIT_BASIS_DECLARED_NOT_VERIFIED]}),
    )
}
