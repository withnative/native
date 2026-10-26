//! Viewer-relative identity disclosure for `list_inbox` items
//! (`native.message-inbox.v3`): who sent a Message, who shares its direct
//! context, what it replies to, and which conversation key groups it.
//!
//! Resolved at page time, for the returned page only, under the viewer's
//! current authority (never frozen into the pinned snapshot): one constant
//! set of batched statements per page, never one per Message. A person is
//! named only when the viewer can see that Person record. A hidden participant
//! is omitted entirely, with no slot and no count, so membership the viewer
//! cannot see is not disclosed; only the single `sender` may be the opaque
//! `state:"hidden"` object.

use std::collections::{BTreeSet, HashMap, HashSet};

use serde_json::{json, Value};
use sqlx::Row;

use crate::error::Result;

use crate::mcp::registry::Caller;

struct ResolvedPerson {
    person_id: String,
    name: String,
}

/// The slot for a resolved person as this viewer may see them, or `None`
/// when the viewer cannot see that Person. The viewer's own slot is always
/// returned, with `name: null` when their own Person record is unreadable to
/// them (kernel v2 applies the same rule).
fn person_slot(
    person: Option<&ResolvedPerson>,
    visible: &HashSet<String>,
    viewer_person: Option<&str>,
) -> Option<Value> {
    let person = person?;
    let viewer = viewer_person == Some(person.person_id.as_str());
    let readable = visible.contains(&person.person_id);
    match (readable, viewer) {
        (true, _) => Some(json!({
            "person_id": person.person_id,
            "name": person.name,
            "viewer": viewer,
            "state": "person",
        })),
        (false, true) => Some(
            json!({"person_id": person.person_id, "name": null, "viewer": true, "state": "person"}),
        ),
        (false, false) => None,
    }
}

/// Identity fields for each of `message_ids`, keyed by Message id. The caller
/// merges the returned object into the item; every id gets an entry.
pub(super) async fn batched_identity_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    message_ids: &[String],
) -> Result<HashMap<String, serde_json::Map<String, Value>>> {
    let mut out: HashMap<String, serde_json::Map<String, Value>> = HashMap::new();
    if message_ids.is_empty() {
        return Ok(out);
    }
    let ids_json = serde_json::to_string(message_ids)?;

    let viewer_person: Option<String> = sqlx::query_scalar(
        "SELECT account.record_id FROM bindings account
           JOIN records person ON person.id=account.record_id
          WHERE account.system='account' AND account.identifier=? AND account.is_canonical=1
            AND person.type='Entity' AND person.kind='person' AND person.deleted_at IS NULL
          ORDER BY account.record_id LIMIT 1",
    )
    .bind(caller.credential())
    .fetch_optional(&mut **tx)
    .await?;

    // (status, origin_type, collection_id) per Message.
    let mut origin_by_id: HashMap<String, (String, Option<String>, Option<String>)> =
        HashMap::new();
    for row in sqlx::query(
        "SELECT message_id,status,origin_type,collection_id
           FROM message_origin_state WHERE message_id IN (SELECT value FROM json_each(?))",
    )
    .bind(&ids_json)
    .fetch_all(&mut **tx)
    .await?
    {
        origin_by_id.insert(
            row.try_get("message_id")?,
            (
                row.try_get("status")?,
                row.try_get("origin_type")?,
                row.try_get("collection_id")?,
            ),
        );
    }

    let mut origin_principals: HashMap<String, Vec<String>> = HashMap::new();
    for row in sqlx::query(
        "SELECT message_id,principal_id FROM message_origin_principals
          WHERE message_id IN (SELECT value FROM json_each(?))
          ORDER BY message_id,principal_id",
    )
    .bind(&ids_json)
    .fetch_all(&mut **tx)
    .await?
    {
        origin_principals
            .entry(row.try_get("message_id")?)
            .or_default()
            .push(row.try_get("principal_id")?);
    }

    let mut sender_by_id: HashMap<String, String> = HashMap::new();
    for row in sqlx::query(
        "SELECT message_id,principal_id FROM message_audiences
          WHERE source='sender' AND message_id IN (SELECT value FROM json_each(?))
          ORDER BY message_id,principal_id",
    )
    .bind(&ids_json)
    .fetch_all(&mut **tx)
    .await?
    {
        sender_by_id
            .entry(row.try_get("message_id")?)
            .or_insert(row.try_get("principal_id")?);
    }

    // Audience principals for a legacy Message (no declared origin): the
    // sender plus its addressees. A declared direct origin names its own.
    let mut legacy_audience: HashMap<String, Vec<String>> = HashMap::new();
    let mut addressed: HashSet<String> = HashSet::new();
    for row in sqlx::query(
        "SELECT message_id,principal_id,source FROM message_audiences
          WHERE source IN ('sender','addressed_to')
            AND message_id IN (SELECT value FROM json_each(?))
          ORDER BY message_id,principal_id",
    )
    .bind(&ids_json)
    .fetch_all(&mut **tx)
    .await?
    {
        let message_id: String = row.try_get("message_id")?;
        let source: String = row.try_get("source")?;
        if source == "addressed_to" {
            addressed.insert(message_id.clone());
        }
        legacy_audience
            .entry(message_id)
            .or_default()
            .push(row.try_get("principal_id")?);
    }

    // (home_id, owner_id) per Message. The owner is the stable authorship
    // fact: a principal later re-pointed at another Person changes who a
    // sender resolves to, never who owns the Message.
    let mut home_by_id: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();
    for row in sqlx::query(
        "SELECT id,home_id,owner_id FROM records WHERE id IN (SELECT value FROM json_each(?))",
    )
    .bind(&ids_json)
    .fetch_all(&mut **tx)
    .await?
    {
        home_by_id.insert(
            row.try_get("id")?,
            (row.try_get("home_id")?, row.try_get("owner_id")?),
        );
    }

    let mut speaker_by_id: HashMap<String, (String, String)> = HashMap::new();
    for row in sqlx::query(
        "SELECT message_id,speaker_kind,assurance FROM message_speakers
          WHERE message_id IN (SELECT value FROM json_each(?))",
    )
    .bind(&ids_json)
    .fetch_all(&mut **tx)
    .await?
    {
        speaker_by_id.insert(
            row.try_get("message_id")?,
            (row.try_get("speaker_kind")?, row.try_get("assurance")?),
        );
    }

    let mut reply_by_id: HashMap<String, String> = HashMap::new();
    for row in sqlx::query(
        "SELECT l.source_id,l.target_id FROM links l
           JOIN records t ON t.id=l.target_id AND t.deleted_at IS NULL
          WHERE l.relationship='reply_to' AND l.source_id IN (SELECT value FROM json_each(?))
          ORDER BY l.source_id,l.target_id",
    )
    .bind(&ids_json)
    .fetch_all(&mut **tx)
    .await?
    {
        reply_by_id
            .entry(row.try_get("source_id")?)
            .or_insert(row.try_get("target_id")?);
    }

    // Principal -> live Person (retained aliases included), once for the page.
    let mut principals: BTreeSet<&str> = BTreeSet::new();
    for list in origin_principals.values() {
        principals.extend(list.iter().map(String::as_str));
    }
    principals.extend(sender_by_id.values().map(String::as_str));
    for list in legacy_audience.values() {
        principals.extend(list.iter().map(String::as_str));
    }
    let principals_json = serde_json::to_string(&principals)?;
    let mut people: HashMap<String, ResolvedPerson> = HashMap::new();
    if !principals.is_empty() {
        for row in sqlx::query(
            "SELECT b.identifier,person.id AS person_id,person.name AS name FROM bindings b
               JOIN records person ON person.id=b.record_id
              WHERE b.system='native-principal'
                AND b.identifier IN (SELECT value FROM json_each(?))
                AND person.type='Entity' AND person.kind='person' AND person.deleted_at IS NULL
              ORDER BY b.identifier,b.is_canonical DESC,person.id",
        )
        .bind(&principals_json)
        .fetch_all(&mut **tx)
        .await?
        {
            people
                .entry(row.try_get("identifier")?)
                .or_insert(ResolvedPerson {
                    person_id: row.try_get("person_id")?,
                    name: row.try_get("name")?,
                });
        }
    }

    // One visibility pass over every Person and reply target we might name.
    let mut to_check: Vec<String> = people
        .values()
        .map(|person| person.person_id.clone())
        .collect();
    to_check.extend(reply_by_id.values().cloned());
    to_check.extend(
        origin_by_id
            .values()
            .filter(|(status, kind, _)| {
                status == "declared" && kind.as_deref() == Some("collection")
            })
            .filter_map(|(_, _, collection)| collection.clone()),
    );
    to_check.sort();
    to_check.dedup();
    let visible = super::super::visible_ids_in(tx, caller, to_check).await?;

    for id in message_ids {
        let mut fields = serde_json::Map::new();
        let origin = origin_by_id.get(id);
        let direct = origin
            .filter(|(status, kind, _)| status == "declared" && kind.as_deref() == Some("direct"));
        let stored = origin_principals.get(id).map(Vec::as_slice).unwrap_or(&[]);

        fields.insert(
            "sender".into(),
            match sender_by_id.get(id).and_then(|principal| {
                person_slot(people.get(principal), &visible, viewer_person.as_deref())
            }) {
                Some(mut sender) => {
                    if let Some((kind, assurance)) = speaker_by_id.get(id) {
                        sender["speaker"] = json!({"kind": kind, "assurance": assurance});
                    }
                    sender
                }
                None => crate::awareness::inbox_hidden_person(),
            },
        );

        // A "note to self": the viewer's own Message (owned by their Person),
        // authored in Unfiled (origin collection `native:unfiled`), with no
        // addressee. Matches the Slack app's old
        // "Notes to self" rule (Unfiled home, sent by the viewer, no addressee).
        let unfiled_origin = origin.is_some_and(|(status, kind, collection)| {
            status == "declared"
                && kind.as_deref() == Some("collection")
                && collection.as_deref() == Some("native:unfiled")
        });
        let in_unfiled = home_by_id
            .get(id)
            .is_some_and(|(home, _)| home.as_deref() == Some("native:unfiled"));
        let owned_by_viewer = viewer_person.is_some()
            && home_by_id
                .get(id)
                .is_some_and(|(_, owner)| owner.as_deref() == viewer_person.as_deref());
        let sent_by_viewer = viewer_person.is_some()
            && sender_by_id
                .get(id)
                .and_then(|principal| people.get(principal))
                .map(|person| person.person_id.as_str())
                == viewer_person.as_deref();
        let is_self = unfiled_origin
            && in_unfiled
            && owned_by_viewer
            && sent_by_viewer
            && !addressed.contains(id);
        let legacy = !matches!(origin, Some((status, _, _)) if status == "declared");

        // Visible participants only: a hidden member adds no slot and no count.
        // A legacy Message stores no origin members, so its participants are
        // its audience (sender and addressees) under the same visibility rule.
        let mut slots: Vec<Value> = Vec::new();
        if direct.is_some() || legacy {
            let members = if legacy {
                legacy_audience.get(id).map(Vec::as_slice).unwrap_or(&[])
            } else {
                stored
            };
            let mut seen: HashSet<&str> = HashSet::new();
            slots = members
                .iter()
                .filter(|principal| {
                    // Aliases of one Person count once.
                    people
                        .get(*principal)
                        .is_none_or(|person| seen.insert(person.person_id.as_str()))
                })
                .filter_map(|principal| {
                    person_slot(people.get(principal), &visible, viewer_person.as_deref())
                })
                .collect();
        } else if is_self {
            slots = sender_by_id
                .get(id)
                .and_then(|principal| {
                    person_slot(people.get(principal), &visible, viewer_person.as_deref())
                })
                .into_iter()
                .collect();
        }
        fields.insert("participant_count".into(), json!(slots.len()));
        fields.insert(
            "participants".into(),
            Value::Array(crate::awareness::inbox_participants(slots)),
        );

        fields.insert(
            "reply_to_id".into(),
            match reply_by_id.get(id) {
                Some(target) if visible.contains(target) => json!(target),
                _ => Value::Null,
            },
        );

        // A direct context has no key in this version (a stable one needs an
        // opaque persisted identity). A Collection is keyed by its id only for a
        // viewer who can see that Collection.
        fields.insert(
            "conversation".into(),
            match origin {
                _ if is_self => json!({"type": "self"}),
                Some((status, kind, collection)) if status == "declared" => {
                    match (kind.as_deref(), collection) {
                        (Some("collection"), Some(collection)) if visible.contains(collection) => {
                            json!({"type": "collection", "key": format!("collection:{collection}")})
                        }
                        (Some("collection"), _) => json!({"type": "collection"}),
                        (Some("direct"), _) => json!({"type": "direct"}),
                        _ => json!({"type": "legacy"}),
                    }
                }
                _ => json!({"type": "legacy"}),
            },
        );
        out.insert(id.clone(), fields);
    }
    Ok(out)
}
