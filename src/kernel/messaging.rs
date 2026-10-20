//! HQ W6: event-owned messaging state. Conversation membership never grants access.
//! The sealed import image includes original side rows for lossless migration;
//! private lanes are served only to their subject and never through history.
use super::*;
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) const PEOPLE_DDL: &str = "CREATE TABLE kernel_message_people (person_id TEXT PRIMARY KEY REFERENCES kernel_records(id), principal_id TEXT NOT NULL UNIQUE REFERENCES kernel_principals(principal_id))";
pub(crate) const DDL: &str = "CREATE TABLE kernel_messages (message_id TEXT PRIMARY KEY REFERENCES kernel_records(id), state TEXT NOT NULL CHECK(json_valid(state)), event_seq INTEGER NOT NULL)";
pub(crate) const CREATED: &str = "kernel.message_created.v1";
#[cfg(feature = "v2-kernel-probe")]
pub(crate) const EVENT: &str = "kernel.message_state.v1";

pub(crate) const RECEIPTS_DDL: &str = "CREATE TABLE kernel_message_receipts (principal_id TEXT NOT NULL, operation_key TEXT NOT NULL, request TEXT NOT NULL, receipt TEXT NOT NULL, PRIMARY KEY(principal_id,operation_key))";
pub(crate) const INTERACTIONS_DDL: &str = "CREATE TABLE kernel_message_interactions(principal_id TEXT NOT NULL,nonce TEXT NOT NULL,operation_key TEXT NOT NULL,PRIMARY KEY(principal_id,nonce))";
pub(crate) const PERSONAS_DDL: &str = "CREATE TABLE kernel_personas(persona_id TEXT PRIMARY KEY REFERENCES kernel_records(id),state TEXT NOT NULL CHECK(json_valid(state)),event_seq INTEGER NOT NULL)";
pub(crate) const COMMAND: &str = "kernel.message_command_committed.v1";
pub(crate) const PERSONA: &str = "kernel.persona_registered.v1";
pub(crate) const RETIRE_PERSONA: &str = "kernel.persona_retired.v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaState {
    pub owner_principal: String,
    pub owner_person_id: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Value>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommandReceipt {
    pub operation_key: String,
    pub request: String,
    pub receipt: Value,
    pub nonce: Option<String>,
}

pub(crate) async fn ensure_schema(conn: &mut SqliteConnection) -> Result<()> {
    super::notifications::ensure_schema(conn).await?;
    for ddl in [RECEIPTS_DDL, INTERACTIONS_DDL, PERSONAS_DDL] {
        sqlx::query(&ddl.replacen("CREATE TABLE", "CREATE TABLE IF NOT EXISTS", 1))
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}
pub(crate) async fn persona_on(
    conn: &mut SqliteConnection,
    id: &str,
) -> Result<Option<PersonaState>> {
    let raw: Option<String> =
        sqlx::query_scalar("SELECT state FROM kernel_personas WHERE persona_id=?")
            .bind(id)
            .fetch_optional(conn)
            .await?;
    raw.map(|v| serde_json::from_str(&v).map_err(Into::into))
        .transpose()
}
pub(crate) async fn fold_persona(
    conn: &mut SqliteConnection,
    id: &str,
    state: &PersonaState,
    seq: i64,
) -> Result<()> {
    if !matches!(state.state.as_str(), "active" | "retired") {
        return Err(Error::engine("invalid persona state"));
    }
    sqlx::query("INSERT INTO kernel_personas VALUES(?,?,?) ON CONFLICT(persona_id) DO UPDATE SET state=excluded.state,event_seq=excluded.event_seq")
        .bind(id).bind(serde_json::to_string(state)?).bind(seq).execute(conn).await?;
    Ok(())
}
pub(crate) async fn project_command(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let state: CommandReceipt = event_payload(event)?;
    let actor = event
        .actor
        .as_deref()
        .ok_or_else(|| Error::engine("message receipt actor missing"))?;
    let known: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id=?)")
            .bind(actor)
            .fetch_one(&mut *conn)
            .await?;
    if !known || state.operation_key.is_empty() {
        return Err(Error::engine("invalid message command receipt"));
    }
    let old: Option<(String,String)> = sqlx::query_as("SELECT request,receipt FROM kernel_message_receipts WHERE principal_id=? AND operation_key=?")
        .bind(actor).bind(&state.operation_key).fetch_optional(&mut *conn).await?;
    if old.is_some_and(|(request, receipt)| {
        request != state.request
            || serde_json::from_str::<Value>(&receipt).ok().as_ref() != Some(&state.receipt)
    }) {
        return Err(Error::conflict("message receipt intent collision"));
    }
    if let Some(nonce) = &state.nonce {
        let used: Option<String> = sqlx::query_scalar("SELECT operation_key FROM kernel_message_interactions WHERE principal_id=? AND nonce=?").bind(actor).bind(nonce).fetch_optional(&mut *conn).await?;
        if used.is_some_and(|key| key != state.operation_key) {
            return Err(Error::conflict("message interaction nonce reused"));
        }
    }
    sqlx::query("INSERT INTO kernel_message_receipts VALUES(?,?,?,?) ON CONFLICT(principal_id,operation_key) DO UPDATE SET request=excluded.request,receipt=excluded.receipt")
        .bind(actor).bind(&state.operation_key).bind(&state.request).bind(serde_json::to_string(&state.receipt)?).execute(&mut *conn).await?;
    if let Some(nonce) = state.nonce {
        sqlx::query("INSERT INTO kernel_message_interactions VALUES(?,?,?) ON CONFLICT(principal_id,nonce) DO NOTHING")
            .bind(actor).bind(nonce).bind(&state.operation_key).execute(conn).await?;
    }
    Ok(())
}
pub(crate) async fn project_persona(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let state: PersonaState = event_payload(event)?;
    let actor = event.actor.as_deref().unwrap_or_default();
    let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records r JOIN kernel_record_fields t ON t.record_id=r.id AND t.name='v1_type' AND t.value_json='\"Entity\"' JOIN kernel_record_fields k ON k.record_id=r.id AND k.name='v1_kind' AND k.value_json='\"persona\"' JOIN kernel_message_people p ON p.person_id=? AND p.principal_id=? WHERE r.id=? AND r.owner_id=?)")
        .bind(&state.owner_person_id).bind(actor).bind(&event.record_id).bind(actor).fetch_one(&mut *conn).await?;
    if !valid || state.owner_principal != actor || state.source.is_some() {
        return Err(Error::engine("invalid owned persona"));
    }
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&event.record_id)
        .fetch_one(&mut *conn)
        .await?;
    let anchor = super::kernel_policy_anchor_on(conn, &home).await?;
    let foreign: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_policy_entries WHERE root_id=? AND (subject_kind!='account' OR subject_id!=? OR effect!='allow'))").bind(anchor).bind(actor).fetch_one(&mut *conn).await?;
    if event.event_type == PERSONA && foreign {
        return Err(Error::engine("persona profile must be owner-only"));
    }
    let previous = persona_on(conn, &event.record_id).await?;
    match (event.event_type.as_str(), previous) {
        (PERSONA, None) if state.state == "active" => (),
        (RETIRE_PERSONA, Some(old))
            if old.state == "active"
                && old.owner_principal == state.owner_principal
                && old.owner_person_id == state.owner_person_id
                && state.state == "retired" => {}
        _ => return Err(Error::engine("invalid persona transition")),
    }
    fold_persona(conn, &event.record_id, &state, event.local_seq).await
}

/// Upgrade early probe receipts before a rebuild discards their projections.
/// The actor and complete committed response are retained as private evidence.
pub(crate) async fn migrate_command_receipts(db: &Db) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    ensure_schema(&mut tx).await?;
    let rows: Vec<(String,String,String,String)> = sqlx::query_as("SELECT principal_id,operation_key,request,receipt FROM kernel_message_receipts r WHERE NOT EXISTS(SELECT 1 FROM main.content_events e WHERE e.type='kernel.message_command_committed.v1' AND e.actor=r.principal_id AND json_extract(e.payload,'$.operation_key')=r.operation_key)")
        .fetch_all(&mut *tx).await?;
    let mut acts = crate::act::ActAllocation::new();
    for (actor, key, request, receipt) in rows {
        let nonce: Option<String> = sqlx::query_scalar("SELECT nonce FROM kernel_message_interactions WHERE principal_id=? AND operation_key=?")
            .bind(&actor).bind(&key).fetch_optional(&mut *tx).await?;
        crate::store::append_in(
            db,
            &mut tx,
            crate::store::AppendSpec {
                record_id: actor.clone(),
                actor: Some(actor),
                event_type: COMMAND.into(),
                payload: serde_json::to_value(CommandReceipt {
                    operation_key: key,
                    request,
                    receipt: serde_json::from_str(&receipt)?,
                    nonce,
                })?,
            },
            &mut acts,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Frozen source semantics needed for live action/decision evidence. Only
/// WorkItem lifecycle declarations and positively terminating values are kept.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageRules {
    pub source_origin: Option<String>,
    pub schemas: Vec<Value>,
    pub positive: BTreeMap<String, std::collections::BTreeSet<String>>,
    pub decision_kinds: std::collections::BTreeSet<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageState {
    /// Historical addressing principals and sender; never a visibility ACL.
    pub audience: BTreeMap<String, String>,
    pub author: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub home_id: Option<String>,
    pub origin: Value,
    pub addressed_to: Vec<String>,
    pub conversations: Vec<String>,
    pub reply_to: Option<String>,
    pub expectation: Option<String>,
    #[serde(default)]
    pub rules: Option<MessageRules>,
    #[serde(default)]
    pub expectations: BTreeMap<String, Value>,
    #[serde(default)]
    pub acknowledgements: BTreeMap<String, String>,
    pub reactions: BTreeMap<String, Vec<String>>,
    /// principal -> lane -> v1-shaped projection row.
    pub private: BTreeMap<String, BTreeMap<String, Value>>,
    /// Original v1 side-table rows; never exposed on ordinary reads.
    pub source: BTreeMap<String, Vec<Value>>,
    pub speaker: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mentions: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mention_origin: Option<String>,
}

/// Payload-free freshness for public reactions and the viewer's own private
/// lane. Ordinary history still withholds every replacement payload. Compare
/// immutable adjacent states rather than exposing or duplicating their data.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn change_as(
    db: &Db,
    principal: &str,
    seq: i64,
) -> Result<Option<KernelHistoryEvent>> {
    let mut tx = db.pool().begin().await?;
    if !hosted_identity::admitted(&mut tx, principal).await? {
        return Ok(None);
    }
    let row: Option<(String, String, Option<String>, String, String, String)> = sqlx::query_as(
        "SELECT record_id,payload,actor,created_at,id,causal_status FROM content_events WHERE seq=? AND type=?",
    )
    .bind(seq)
    .bind(EVENT)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((record, raw, actor, created_at, id, causal_status)) = row else {
        return Ok(None);
    };
    if !legacy_history::visible(&mut tx, principal, &record, &mut BTreeMap::new()).await? {
        return Ok(None);
    }
    let previous: Option<String> = sqlx::query_scalar(
        "SELECT CASE WHEN type='kernel.v1_state_imported.v1' THEN json_extract(payload,'$.state.message') ELSE payload END
         FROM content_events WHERE record_id=? AND seq<? AND
         (type IN ('kernel.message_created.v1','kernel.message_state.v1') OR
          (type='kernel.v1_state_imported.v1' AND json_type(payload,'$.state.message')='object'))
         ORDER BY seq DESC LIMIT 1",
    ).bind(&record).bind(seq).fetch_optional(&mut *tx).await?;
    let Some(previous) = previous else {
        return Ok(None);
    };
    let before: MessageState = serde_json::from_str(&previous)?;
    let after: MessageState = serde_json::from_str(&raw)?;
    if before.reactions == after.reactions
        && before.private.get(principal) == after.private.get(principal)
        && before.acknowledgements.get(principal) == after.acknowledgements.get(principal)
    {
        return Ok(None);
    }
    let root_view = kernel_effective_capability_on(&mut tx, principal, KERNEL_ROOT_ID)
        .await?
        .allows(Capability::View);
    let actor = actor.filter(|actor| actor == principal || root_view);
    let actor_name = if let Some(actor) = &actor {
        sqlx::query_scalar("SELECT display_label FROM kernel_principals WHERE principal_id=?")
            .bind(actor)
            .fetch_optional(&mut *tx)
            .await?
    } else {
        None
    };
    Ok(Some(KernelHistoryEvent {
        retained_legacy: None,
        id,
        run_key: None,
        causal_status,
        seq,
        event_type: EVENT.into(),
        record_id: record,
        actor,
        actor_name,
        created_at,
    }))
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn communication_origin(
    conn: &mut SqliteConnection,
    state: &MessageState,
) -> Result<Value> {
    Ok(match state.origin["type"].as_str() {
        Some("collection") => {
            let id = &state.origin["collection_id"];
            serde_json::json!({"type":"collection","collection_id":id,"context_key":format!("collection:{}",id.as_str().unwrap_or_default())})
        }
        Some("direct") => {
            let mut principals = Vec::new();
            if let Some(people) = state.origin["participant_ids"].as_array() {
                for person in people {
                    let principal: Option<String> = sqlx::query_scalar(
                        "SELECT principal_id FROM kernel_message_people WHERE person_id=?",
                    )
                    .bind(person.as_str().unwrap_or_default())
                    .fetch_optional(&mut *conn)
                    .await?;
                    let Some(principal) = principal else {
                        return Ok(serde_json::json!({"type":"legacy_unknown"}));
                    };
                    principals.push(principal);
                }
            }
            principals.sort();
            principals.dedup();
            serde_json::json!({"type":"direct","context_key":crate::events::direct_origin_context_key(&principals),"principals":principals})
        }
        _ => serde_json::json!({"type":"legacy_unknown"}),
    })
}

pub(crate) async fn on(conn: &mut SqliteConnection, id: &str) -> Result<Option<MessageState>> {
    let raw: Option<String> =
        sqlx::query_scalar("SELECT state FROM kernel_messages WHERE message_id=?")
            .bind(id)
            .fetch_optional(conn)
            .await?;
    raw.map(|v| serde_json::from_str(&v).map_err(Into::into))
        .transpose()
}

pub(crate) async fn fold(
    conn: &mut SqliteConnection,
    id: &str,
    state: &MessageState,
    seq: i64,
) -> Result<()> {
    for (principal, capability) in &state.audience {
        parse_kernel_capability(capability)?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id=?)",
        )
        .bind(principal)
        .fetch_one(&mut *conn)
        .await?;
        if !exists {
            return Err(Error::engine("message audience has unresolved principal"));
        }
    }
    sqlx::query("INSERT INTO kernel_messages VALUES(?,?,?) ON CONFLICT(message_id) DO UPDATE SET state=excluded.state,event_seq=excluded.event_seq")
        .bind(id).bind(serde_json::to_string(state)?).bind(seq).execute(conn).await?;
    Ok(())
}

/// Recognize native and imported Messages for authorship retention during
/// offboarding. Persisted message state remains authoritative if the carrier
/// field is absent or malformed. This predicate grants no read authority.
pub async fn is_message_record(conn: &mut SqliteConnection, id: &str) -> Result<bool> {
    if sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM kernel_messages WHERE message_id=?)",
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await?
    {
        return Ok(true);
    }
    #[allow(clippy::type_complexity)]
    let row: Option<(Option<String>,Option<i64>,Option<String>,Option<String>,Option<String>)> = sqlx::query_as("SELECT r.pin_family,r.pin_version,r.primary_type,r.kind,f.value_json FROM kernel_records r LEFT JOIN kernel_record_fields f ON f.record_id=r.id AND f.name='v1_type' WHERE r.id=?").bind(id).fetch_optional(conn).await?;
    let Some((family, version, primary_type, kind, raw)) = row else {
        return Ok(false);
    };
    let mut fields = serde_json::Map::new();
    if let Some(raw) = raw {
        fields.insert("v1_type".into(), serde_json::from_str(&raw)?);
    }
    Ok(crate::v2_standard::v1_compat::preserves_message_authorship(
        family.as_deref(),
        version.and_then(|v| u32::try_from(v).ok()),
        primary_type.as_deref(),
        kind.as_deref(),
        &fields,
    ))
}

pub(crate) use is_message_record as is_message;

/// Addressing is data. Missing state and reserved maintenance identities deny;
/// canonical current home policy and owner authority govern all other reads.
pub(crate) async fn capability(
    conn: &mut SqliteConnection,
    principal: &str,
    id: &str,
) -> Result<Option<Capability>> {
    if !is_message_record(conn, id).await? {
        return Ok(None);
    }
    let maintenance: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id=? AND auth_binding=?)",
    )
    .bind(principal)
    .bind(super::relates_to_port::HOST_TRANSFORM_BINDING)
    .fetch_one(&mut *conn)
    .await?;
    Ok((maintenance || on(conn, id).await?.is_none()).then_some(Capability::None))
}

/// Message/bearer guard over a caller's already evaluated home-policy snapshot.
/// `homes` selects `id,view` for valid homes. This shares live hosted membership
/// and imported member-policy evaluation with ordinary kernel authorization.
pub(crate) fn sql_guard(alias: &str, actor: &str, homes: &str) -> String {
    format!(
        r#"NOT EXISTS(
      WITH RECURSIVE bearers(id,depth) AS (
        SELECT {alias}.id,0 UNION ALL
        SELECT l.target_id,b.depth+1 FROM bearers b
        JOIN kernel_generic_links l ON l.source_id=b.id AND l.active=1 AND l.relationship='part_of'
        JOIN kernel_record_fields f ON f.record_id=b.id AND f.name='v1_type' AND f.value_json IN ('"Annotation"','"Document"')
        WHERE b.depth<8)
      SELECT 1 FROM bearers b WHERE
        ((EXISTS(SELECT 1 FROM kernel_messages known WHERE known.message_id=b.id)
          OR EXISTS(SELECT 1 FROM kernel_records carrier WHERE carrier.id=b.id AND
            ((carrier.pin_family='native.v1.record' AND carrier.pin_version=1 AND EXISTS(SELECT 1 FROM kernel_record_fields f WHERE f.record_id=b.id AND f.name='v1_type' AND f.value_json='"Message"'))
             OR (carrier.primary_type='Message' AND NOT coalesce(carrier.pin_family='native.v1.record' AND carrier.pin_version=1,0)))))
         AND NOT EXISTS(
            SELECT 1 FROM kernel_messages m JOIN kernel_records mr ON mr.id=m.message_id
            JOIN ({homes}) current_home ON current_home.id=mr.home_id
            WHERE m.message_id=b.id
            AND (current_home.view OR mr.owner_id={actor})
            AND NOT EXISTS(SELECT 1 FROM kernel_principals service WHERE service.principal_id={actor} AND service.auth_binding='host:relates-to:transform')
            AND NOT EXISTS(SELECT 1 FROM kernel_import_tombstones tomb WHERE tomb.record_id=mr.id)))
        OR (b.depth=8
          AND EXISTS(SELECT 1 FROM kernel_record_fields f WHERE f.record_id=b.id AND f.name='v1_type' AND f.value_json IN ('"Annotation"','"Document"'))
          AND EXISTS(SELECT 1 FROM kernel_generic_links l WHERE l.source_id=b.id AND l.active=1 AND l.relationship='part_of'))
    )"#
    )
}

pub(crate) async fn audience_allows(
    conn: &mut SqliteConnection,
    actor: &str,
    id: &str,
) -> Result<bool> {
    if !hosted_identity::admitted(conn, actor).await? {
        return Ok(false);
    }
    let bearers: Vec<(String,bool)> = sqlx::query_as(r#"WITH RECURSIVE bearers(id,depth) AS (
        SELECT ?1,0 UNION ALL
        SELECT l.target_id,b.depth+1 FROM bearers b
        JOIN kernel_generic_links l ON l.source_id=b.id AND l.active=1 AND l.relationship='part_of'
        JOIN kernel_record_fields f ON f.record_id=b.id AND f.name='v1_type' AND f.value_json IN ('"Annotation"','"Document"') WHERE b.depth<8)
        SELECT b.id,(b.depth=8 AND EXISTS(SELECT 1 FROM kernel_record_fields f WHERE f.record_id=b.id AND f.name='v1_type' AND f.value_json IN ('"Annotation"','"Document"')) AND EXISTS(SELECT 1 FROM kernel_generic_links l WHERE l.source_id=b.id AND l.active=1 AND l.relationship='part_of')) FROM bearers b"#).bind(id).fetch_all(&mut *conn).await?;
    for (bearer, overflow) in bearers {
        if overflow {
            return Ok(false);
        }
        if is_message_record(conn, &bearer).await?
            && (capability(conn, actor, &bearer).await? == Some(Capability::None)
                || hq::tombstoned_on(conn, &bearer).await?
                || !super::kernel_base_capability_on(conn, actor, &bearer, false)
                    .await?
                    .allows(Capability::View))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Retained events rebuild without consulting a member's current admission.
/// Structural seals and per-subject mutation validation still apply.
pub(crate) async fn replay(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if event.event_type == DEST_SET {
        project_destination_in(conn, event, true).await?;
    } else {
        project_in(conn, event, true).await?;
    }
    super::record_metadata::touch_event(conn, event).await
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    project_in(conn, event, false).await
}
async fn project_in(conn: &mut SqliteConnection, event: &EventRow, replaying: bool) -> Result<()> {
    let state: MessageState = event_payload(event)?;
    let actor = event.actor.as_deref().unwrap_or("");
    if event.event_type == CREATED {
        let same_act: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE record_id=? AND type='kernel.record_created.v1' AND actor=? AND act=? AND seq<?)")
            .bind(&event.record_id).bind(actor).bind(event.act).bind(event.local_seq).fetch_one(&mut *conn).await?;
        if !same_act
            || on(conn, &event.record_id).await?.is_some()
            || state.author.as_deref() != Some(actor)
            || state.audience.get(actor).map(String::as_str) != Some("manage")
            || !state.private.is_empty()
            || !state.source.is_empty()
            || !state.reactions.is_empty()
        {
            return Err(Error::engine("invalid sealed message creation"));
        }
        if let Some(speaker) = &state.speaker {
            let persona = persona_on(conn, speaker["id"].as_str().unwrap_or_default())
                .await?
                .ok_or_else(|| Error::engine("speaker not found"))?;
            if persona.owner_principal != actor
                || persona.state != "active"
                || speaker["kind"] != "persona"
                || speaker["assurance"] != "client_asserted"
            {
                return Err(Error::engine("speaker not found"));
            }
        }
        let mut mention_ids = std::collections::BTreeSet::new();
        for value in &state.mentions {
            // Binding and effective status are derived by the kernel executor.
            let mut input = value.clone();
            input
                .as_object_mut()
                .ok_or_else(|| Error::engine("invalid mention"))?
                .remove("target_binding");
            input.as_object_mut().unwrap().remove("effective");
            let mention: crate::awareness::MentionInput = serde_json::from_value(input)?;
            if mention.mention_id.trim().is_empty()
                || !mention_ids.insert(mention.mention_id.clone())
            {
                return Err(Error::engine("invalid mention id"));
            }
            if !replaying {
                kernel_require_on(conn, actor, &mention.target_id, Capability::View).await?;
            }
            let expected = match mention.target_kind.as_str() {
                "principal" if state.addressed_to.contains(&mention.target_id) => {
                    let principal: String = sqlx::query_scalar(
                        "SELECT principal_id FROM kernel_message_people WHERE person_id=?",
                    )
                    .bind(&mention.target_id)
                    .fetch_one(&mut *conn)
                    .await?;
                    format!("native/{principal}")
                }
                "record" => crate::identity::encode_native_record(
                    state.mention_origin.as_deref().unwrap_or_default(),
                    &mention.target_id,
                )?,
                _ => return Err(Error::engine("invalid mention target")),
            };
            if value["target_binding"].as_str() != Some(&expected) || value["effective"] != true {
                return Err(Error::engine("invalid mention binding"));
            }
        }
        fold(conn, &event.record_id, &state, event.local_seq).await?;
        return super::notifications::project(conn, event, None, &state).await;
    }
    let previous = on(conn, &event.record_id)
        .await?
        .ok_or_else(|| Error::engine("message state missing"))?;
    if previous.created_at != state.created_at
        || previous.home_id != state.home_id
        || previous.audience != state.audience
        || previous.author != state.author
        || previous.origin != state.origin
        || previous.addressed_to != state.addressed_to
        || previous.reply_to != state.reply_to
        || previous.source != state.source
        || previous.speaker != state.speaker
        || previous.mentions != state.mentions
        || previous.mention_origin != state.mention_origin
        || previous.expectation != state.expectation
        || previous.expectations != state.expectations
        || previous.rules != state.rules
    {
        return Err(Error::engine("sealed message content cannot change"));
    }
    if !replaying {
        kernel_require_on(conn, actor, &event.record_id, Capability::View).await?;
    }
    // A subject may change only their own personal lanes and reactions.
    let mut permitted = previous.clone();
    if let Some(evidence) = state.acknowledgements.get(actor) {
        let person: Option<String> =
            sqlx::query_scalar("SELECT person_id FROM kernel_message_people WHERE principal_id=?")
                .bind(actor)
                .fetch_optional(&mut *conn)
                .await?;
        if state.expectation.as_deref() != Some("ack")
            || !person.is_some_and(|p| state.addressed_to.contains(&p))
            || evidence != &event.record_id
        {
            return Err(Error::engine(
                "acknowledgement requires the caller's addressed ack expectation",
            ));
        }
        permitted
            .acknowledgements
            .insert(actor.into(), evidence.clone());
    }
    if let Some(lanes) = state.private.get(actor) {
        permitted.private.insert(actor.into(), lanes.clone());
    }
    if let Some(reactions) = state.reactions.get(actor) {
        permitted.reactions.insert(actor.into(), reactions.clone());
    } else {
        permitted.reactions.remove(actor);
    }
    if previous.conversations != state.conversations {
        if !replaying {
            kernel_require_on(conn, actor, &event.record_id, Capability::Edit).await?;
            for id in &state.conversations {
                kernel_require_on(conn, actor, id, Capability::View).await?;
            }
        }
        permitted.conversations = state.conversations.clone();
    }
    if permitted != state {
        return Err(Error::engine(
            "message mutation crosses private subject boundary",
        ));
    }
    fold(conn, &event.record_id, &state, event.local_seq).await?;
    super::notifications::project(conn, event, Some(&previous), &state).await
}
async fn kernel_require_on(
    conn: &mut SqliteConnection,
    principal: &str,
    id: &str,
    required: Capability,
) -> Result<()> {
    if !kernel_effective_capability_on(conn, principal, id)
        .await?
        .allows(required)
    {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    Ok(())
}

pub(crate) const DEST_DDL:&str="CREATE TABLE kernel_message_destinations(principal_id TEXT NOT NULL REFERENCES kernel_principals(principal_id),collection_id TEXT NOT NULL,state TEXT NOT NULL,event_seq INTEGER NOT NULL,imported INTEGER NOT NULL,PRIMARY KEY(principal_id,collection_id))";
pub(crate) const DEST_IMPORT: &str = "kernel.message_destination_imported.v1";
pub(crate) const DEST_SET: &str = "kernel.message_destination_set.v1";
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Destination {
    pub principal_id: String,
    pub collection_id: String,
    pub state: Value,
}
pub(crate) async fn destination_on(
    conn: &mut SqliteConnection,
    principal: &str,
    collection: &str,
) -> Result<Option<Value>> {
    let raw: Option<String> = sqlx::query_scalar(
        "SELECT state FROM kernel_message_destinations WHERE principal_id=? AND collection_id=?",
    )
    .bind(principal)
    .bind(collection)
    .fetch_optional(conn)
    .await?;
    raw.map(|v| serde_json::from_str(&v).map_err(Into::into))
        .transpose()
}
pub(crate) async fn project_destination(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    project_destination_in(conn, event, false).await
}
async fn project_destination_in(
    conn: &mut SqliteConnection,
    event: &EventRow,
    replaying: bool,
) -> Result<()> {
    let value: Destination = event_payload(event)?;
    let imported = event.event_type == DEST_IMPORT;
    if imported {
        hq::require_import(conn, event.actor.as_deref().unwrap_or("")).await?;
    } else if event.event_type != DEST_SET
        || event.actor.as_deref() != Some(value.principal_id.as_str())
    {
        return Err(Error::engine("destination is principal-private"));
    }
    if value.collection_id.trim().is_empty()
        || value.state["version"].as_i64().is_none_or(|v| v < 1)
        || !matches!(value.state["joined_by"].as_str(), Some("send" | "explicit"))
    {
        return Err(Error::engine("invalid private destination state"));
    }
    let present = value.state["present"]
        .as_bool()
        .or_else(|| {
            value.state["present"]
                .as_i64()
                .filter(|v| matches!(v, 0 | 1))
                .map(|v| v != 0)
        })
        .ok_or_else(|| Error::engine("invalid destination presence"))?;
    if !imported && present {
        let target = if value.collection_id == "native:root" {
            KERNEL_ROOT_ID
        } else {
            &value.collection_id
        };
        if !replaying {
            kernel_require_on(conn, &value.principal_id, target, Capability::View).await?;
        }
        if target != KERNEL_ROOT_ID {
            let collection:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_record_fields WHERE record_id=? AND name='v1_type' AND value_json='\"Collection\"')").bind(target).fetch_one(&mut *conn).await?;
            if !collection {
                return Err(Error::engine(HIDDEN_OR_MISSING));
            }
        }
    }
    if !imported {
        let old = destination_on(conn, &value.principal_id, &value.collection_id).await?;
        let version = old
            .as_ref()
            .and_then(|v| v["version"].as_i64())
            .unwrap_or(0);
        if value.state["version"].as_i64() != Some(version + 1) {
            return Err(Error::conflict("destination version conflict"));
        }
    }
    sqlx::query("INSERT INTO kernel_message_destinations VALUES(?,?,?,?,?) ON CONFLICT(principal_id,collection_id) DO UPDATE SET state=excluded.state,event_seq=excluded.event_seq,imported=excluded.imported")
        .bind(&value.principal_id).bind(&value.collection_id).bind(serde_json::to_string(&value.state)?).bind(event.local_seq).bind(imported).execute(conn).await?;
    Ok(())
}
pub(crate) async fn import_destination(
    db: &Db,
    host: &str,
    value: &Destination,
) -> Result<hq::ImportResult> {
    let mut tx = begin_write(db.write_pool()).await?;
    hq::require_import(&mut tx, host).await?;
    hq::require_source_import_open(&mut tx).await?;
    let existing:Option<(String,bool)>=sqlx::query_as("SELECT state,imported FROM kernel_message_destinations WHERE principal_id=? AND collection_id=?").bind(&value.principal_id).bind(&value.collection_id).fetch_optional(&mut *tx).await?;
    let result = if let Some((old, imported)) = existing {
        if !imported {
            return Err(Error::conflict(
                "native private destination requires import review",
            ));
        }
        if serde_json::from_str::<Value>(&old)? == value.state {
            return Ok(hq::ImportResult::Unchanged);
        }
        hq::ImportResult::Updated
    } else {
        hq::ImportResult::Created
    };
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: value.principal_id.clone(),
            event_type: DEST_IMPORT.into(),
            payload: serde_json::to_value(value)?,
            actor: Some(host.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(result)
}

/// Deletion preserves Message content and attribution, while retiring its live
/// mention/notification projections exactly as v1's tombstone does.
pub(crate) async fn deleted_on(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if let Some(mut state) = on(conn, &event.record_id).await? {
        for mention in &mut state.mentions {
            let mention = mention
                .as_object_mut()
                .ok_or_else(|| Error::engine("invalid retained Message mention"))?;
            mention.insert("effective".into(), Value::Bool(false));
        }
        sqlx::query("UPDATE kernel_messages SET state=?,event_seq=? WHERE message_id=?")
            .bind(serde_json::to_string(&state)?)
            .bind(event.local_seq)
            .bind(&event.record_id)
            .execute(&mut *conn)
            .await?;
        super::notifications::deleted_on(conn, event).await?;
    }
    Ok(())
}
