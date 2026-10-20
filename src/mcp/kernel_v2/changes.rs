//! Payload-free synchronization using the ordinary kernel history disclosure
//! rules. Empty polls seek the sequence index; no record enumeration is needed.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Order {
    #[default]
    OldestFirst,
    NewestFirst,
}
#[derive(Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ActorScope {
    #[default]
    All,
    #[serde(rename = "self")]
    Self_,
    Others,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    #[serde(alias = "after_seq")]
    after_local_seq: Option<i64>,
    #[serde(alias = "through_seq")]
    through_local_seq: Option<i64>,
    limit: Option<usize>,
    #[serde(default)]
    actor_scope: ActorScope,
    #[serde(default)]
    order: Order,
}

pub(super) async fn whats_changed(db: &Db, actor: &str, arguments: Value) -> Result<Value> {
    let args: Args = parse("whats_changed", arguments.clone())?;
    let limit = args.limit.unwrap_or(200);
    if !(1..=1000).contains(&limit) {
        return Err(Error::engine(
            "whats_changed limit must be between 1 and 1000",
        ));
    }
    let newest = matches!(args.order, Order::NewestFirst);
    let head: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(db.pool())
        .await?;
    let high = args.through_local_seq.unwrap_or(head).min(head);
    let after = args
        .after_local_seq
        .unwrap_or(if newest { i64::MAX } else { 0 });
    if high < 0 || after < 0 {
        return Err(Error::engine("whats_changed cursors must be nonnegative"));
    }
    let mut cursor = after;
    let mut matched = Vec::new();
    let mut has_more = false;
    let comparison = if newest { "<" } else { ">" };
    let direction = if newest { "DESC" } else { "ASC" };
    let mut scanned = 0;
    const SCAN_BUDGET: usize = 1024;
    'scan: loop {
        // Budget bounds work even when every event is withheld. Only the
        // opaque log cursor advances; no hidden identifiers or counts escape.
        let rows: Vec<(i64, String, String)> = sqlx::query_as(&format!(
            "SELECT seq,record_id,type FROM content_events WHERE seq {comparison} ? AND seq<=? ORDER BY seq {direction} LIMIT 256"
        )).bind(cursor).bind(high).fetch_all(db.pool()).await?;
        if rows.is_empty() {
            cursor = if newest { 0 } else { high.max(after) };
            break;
        }
        let batch_start = if newest {
            cursor.min(high.saturating_add(1))
        } else {
            cursor
        };
        let mut histories = BTreeMap::new();
        for (_, subject, _) in &rows {
            if let std::collections::btree_map::Entry::Vacant(entry) =
                histories.entry(subject.clone())
            {
                // Canonical history owns all disclosure: Message/attachment/
                // comment bearers, link endpoints, retained v1 dependencies,
                // private commands and actor/run attribution. Metadata only.
                let events = kernel::history_page_in_range_as(
                    db,
                    actor,
                    subject,
                    Some(batch_start),
                    newest,
                    256,
                    false,
                    false,
                    (
                        rows.first().unwrap().0.min(rows.last().unwrap().0),
                        rows.first().unwrap().0.max(rows.last().unwrap().0),
                    ),
                )
                .await?;
                entry.insert(
                    events
                        .into_iter()
                        .map(|e| (e.seq, e))
                        .collect::<BTreeMap<_, _>>(),
                );
            }
        }
        let fetched = rows.len();
        for (seq, subject, kind) in rows {
            let event = if kind == kernel::messaging::EVENT {
                kernel::messaging::change_as(db, actor, seq).await?
            } else {
                histories
                    .get_mut(&subject)
                    .and_then(|events| events.remove(&seq))
            };
            if let Some(event) = event {
                let accepted = match args.actor_scope {
                    ActorScope::All => true,
                    ActorScope::Self_ => event.actor.as_deref() == Some(actor),
                    ActorScope::Others => event.actor.as_deref() != Some(actor),
                };
                if accepted {
                    if matched.len() == limit {
                        has_more = true;
                        break 'scan;
                    }
                    matched.push(event);
                }
            }
            cursor = seq;
            scanned += 1;
        }
        if scanned >= SCAN_BUDGET && fetched == 256 {
            has_more = true;
            break;
        }
        if fetched < 256 {
            cursor = if newest { 0 } else { high.max(after) };
            break;
        }
    }
    let count = matched.len();
    let changes: Vec<Value> = matched
        .into_iter()
        .map(|event| {
            let family = if event.event_type.contains("created") {
                "created"
            } else {
                "updated"
            };
            json!({
                "record_id":event.record_id,"record_name":null,"record_type":null,
                "actor":event.actor,"actor_name":event.actor_name,"run_key":event.run_key,
                "channel":{"kind":"unknown","assurance":"unknown_or_withheld"},
                "executor":{"kind":null,"assurance":"unknown_or_withheld"},
                "first_local_seq":event.seq,"last_local_seq":event.seq,
                "first_event_at":event.created_at,"last_event_at":event.created_at,
                "event_count":1,"event_types":BTreeSet::from([event.event_type]),
                "event_families":[family],"changed_fields":[]
            })
        })
        .collect();
    let next = has_more.then_some(cursor);
    let next_request = next.map(|next| {
        let mut request = arguments;
        request["after_local_seq"] = json!(next);
        request
            .as_object_mut()
            .expect("parsed object")
            .remove("after_seq");
        request["through_local_seq"] = json!(high);
        request
            .as_object_mut()
            .expect("parsed object")
            .remove("through_seq");
        request
    });
    Ok(json!({
        "local_database_id":db.realtime_hub().map(|hub|hub.database_identity().to_owned()),
        "after_local_seq":after,"scanned_through_local_seq":cursor,
        "high_water_local_seq":high,"next_after_local_seq":next,"has_more":has_more,
        "scanned_event_count":count,"matched_event_count":count,
        "changes":changes,"next_request":next_request
    }))
}
