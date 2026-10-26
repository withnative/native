//! Recipient-private, replayed notification projections. Content events own
//! the transitions; these tables are never ordinary records or public events.
use super::*;
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub(crate) const PREFERENCE_EVENT: &str = "kernel.notification_preference_set.v1";
pub(crate) const PREFERENCES_DDL: &str = "CREATE TABLE kernel_notification_preferences(principal_id TEXT PRIMARY KEY,arrival TEXT NOT NULL CHECK(arrival IN ('all','dms_and_mentions','off')))";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Arrival {
    All,
    DmsAndMentions,
    Off,
}
impl Arrival {
    fn as_str(&self) -> &'static str {
        match self {
            Self::All => "all",
            Self::DmsAndMentions => "dms_and_mentions",
            Self::Off => "off",
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreferenceSet {
    arrival: Arrival,
}

pub(crate) async fn require_account_on(conn: &mut SqliteConnection, principal: &str) -> Result<()> {
    let account: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id=? AND kind='account' AND auth_binding IS NOT NULL AND auth_binding NOT LIKE 'host:%')")
        .bind(principal).fetch_one(conn).await?;
    if !account {
        return Err(Error::engine(
            "notification preference requires an authenticated account principal",
        ));
    }
    Ok(())
}

pub(crate) async fn project_preference(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let logged: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE seq=? AND id=? AND record_id=? AND type=? AND actor IS ? AND payload IS ? AND created_at=?)")
        .bind(event.local_seq).bind(&event.id).bind(&event.record_id).bind(&event.event_type).bind(&event.actor).bind(&event.payload).bind(&event.created_at).fetch_one(&mut *conn).await?;
    if !logged {
        return Err(Error::engine(
            "notification preference projection requires the kernel-issued logged event",
        ));
    }
    let value: PreferenceSet = event_payload(event)?;
    let actor = event.actor.as_deref().unwrap_or_default();
    require_account_on(conn, actor).await?;
    if event.record_id != actor {
        return Err(Error::engine("invalid account notification preference"));
    }
    sqlx::query("INSERT INTO kernel_notification_preferences VALUES(?,?) ON CONFLICT(principal_id) DO UPDATE SET arrival=excluded.arrival")
        .bind(actor).bind(value.arrival.as_str()).execute(conn).await?;
    Ok(())
}

pub(crate) async fn arrival_on(conn: &mut SqliteConnection, principal: &str) -> Result<String> {
    Ok(sqlx::query_scalar(
        "SELECT arrival FROM kernel_notification_preferences WHERE principal_id=?",
    )
    .bind(principal)
    .fetch_optional(conn)
    .await?
    .unwrap_or_else(|| "all".into()))
}

/// Explicit preparation repairs this projection from its sealed events. Merely
/// creating an empty table would falsely reset a preference after projection
/// loss. Serving/opening never invokes this repair.
pub(crate) async fn prepare_preferences_on(conn: &mut SqliteConnection) -> Result<()> {
    ensure_schema(conn).await?;
    sqlx::query("DELETE FROM kernel_notification_preferences")
        .execute(&mut *conn)
        .await?;
    let rows = sqlx::query("SELECT *, (SELECT json_group_array(parent_event_id) FROM content_event_causal_frontier WHERE event_id=content_events.id) AS causal_frontier FROM content_events WHERE type=? ORDER BY seq")
        .bind(PREFERENCE_EVENT).fetch_all(&mut *conn).await?;
    for row in rows {
        let event = crate::query::events::event_from_row(&row)?;
        project_preference(conn, &event).await?;
    }
    Ok(())
}

/// Native admitted sends are delivered. Imported Messages require retained
/// delivery evidence, not merely a declared audience or an editable record.
/// Eligibility uses projections already folded, so replay never sees a future
/// import roster or retained delivery header.
async fn conversation_on(
    conn: &mut SqliteConnection,
    id: &str,
) -> Result<Vec<(String, MessageState)>> {
    let rows: Vec<(String,String)> = sqlx::query_as(r#"
        WITH RECURSIVE delivered(id,reply_to) AS MATERIALIZED (
          SELECT m.message_id,json_extract(m.state,'$.reply_to') FROM kernel_messages m
          WHERE EXISTS(SELECT 1 FROM content_events e WHERE e.record_id=m.message_id
            AND e.type='kernel.message_created.v1' AND e.seq<=m.event_seq)
          OR EXISTS(SELECT 1 FROM kernel_legacy_sql_events h JOIN content_events e ON e.seq=h.seq
            WHERE h.record_id=m.message_id AND h.source_stream='content_events'
            AND (h.event_type='message.delivery.authorized.v1'
              OR (h.event_type='message.send_evaluated.v1' AND json_extract(e.payload,'$.legacy.payload.delivered')=1)))
        ), thread(id) AS (
          SELECT ? UNION
          SELECT d.reply_to FROM thread t JOIN delivered d ON d.id=t.id JOIN delivered target ON target.id=d.reply_to
          UNION
          SELECT d.id FROM thread t JOIN delivered current ON current.id=t.id JOIN delivered d ON d.reply_to=t.id
        )
        SELECT m.message_id,m.state FROM thread t JOIN kernel_messages m ON m.message_id=t.id ORDER BY m.message_id
    "#).bind(id).fetch_all(conn).await?;
    rows.into_iter()
        .map(|(id, raw)| Ok((id, serde_json::from_str(&raw)?)))
        .collect()
}

fn direct_set(state: &MessageState) -> Option<BTreeSet<String>> {
    (state.origin["type"] == "direct").then(|| {
        state.origin["participant_ids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    })
}

async fn conversation_muted_on(
    conn: &mut SqliteConnection,
    principal: &str,
    id: &str,
    state: &MessageState,
) -> Result<bool> {
    // Most accounts have no mutes. Read only that account's muted Messages
    // before paying for a thread walk or decoding direct-context siblings.
    let rows: Vec<(String,String)> = sqlx::query_as("SELECT m.message_id,m.state FROM kernel_messages m WHERE EXISTS(SELECT 1 FROM json_each(m.state,'$.private') p WHERE p.key=? AND json_extract(p.value,'$.preference.muted')=1) ORDER BY m.message_id")
        .bind(principal).fetch_all(&mut *conn).await?;
    if rows.is_empty() {
        return Ok(false);
    }
    let mut muted = BTreeSet::new();
    let own = direct_set(state);
    for (other_id, raw) in rows {
        if other_id == id {
            return Ok(true);
        }
        if let Some(own) = &own {
            let other: MessageState = serde_json::from_str(&raw)?;
            if direct_set(&other).as_ref() == Some(own) {
                return Ok(true);
            }
        }
        muted.insert(other_id);
    }
    Ok(conversation_on(conn, id)
        .await?
        .iter()
        .any(|(id, _)| muted.contains(id)))
}

async fn routine_arrivals(
    conn: &mut SqliteConnection,
    event: &EventRow,
    state: &MessageState,
) -> Result<()> {
    let mut recipients = BTreeSet::new();
    if let Some(people) = direct_set(state) {
        for person in people {
            let principal: Option<String> = sqlx::query_scalar(
                "SELECT principal_id FROM kernel_message_people WHERE person_id=?",
            )
            .bind(person)
            .fetch_optional(&mut *conn)
            .await?;
            recipients.extend(principal);
        }
    }
    if state.reply_to.is_some() {
        for (_, message) in conversation_on(conn, &event.record_id).await? {
            recipients.extend(message.author);
        }
    }
    for principal in recipients {
        if state.author.as_deref() == Some(&principal) {
            continue;
        }
        let held:bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_message_candidates WHERE principal_id=? AND message_id=? AND json_extract(state,'$.status')='effective' AND json_extract(state,'$.reason') IN ('principal_mention','human_obligation'))")
            .bind(&principal).bind(&event.record_id).fetch_one(&mut *conn).await?;
        if held
            || !hosted_identity::notification_creation_capability_on(conn, &principal, event)
                .await?
                .allows(Capability::View)
            || !crate::awareness::arrival_preference_allows(
                &arrival_on(conn, &principal).await?,
                "routine_arrival",
                direct_set(state).is_some(),
            )
            || conversation_muted_on(conn, &principal, &event.record_id, state).await?
        {
            continue;
        }
        propose(
            conn,
            event,
            &principal,
            "routine_arrival",
            None,
            "routine-arrival-v1",
            "recipient_policy",
        )
        .await?;
    }
    Ok(())
}

#[cfg(feature = "v2-kernel-probe")]
async fn current_allows(conn: &mut SqliteConnection, principal: &str, row: &Value) -> Result<bool> {
    if row["reason"] != "routine_arrival" {
        return Ok(true);
    }
    let id = row["message_id"].as_str().unwrap_or_default();
    let Some(state) = messaging::on(conn, id).await? else {
        return Ok(false);
    };
    Ok(crate::awareness::arrival_preference_allows(
        &arrival_on(conn, principal).await?,
        "routine_arrival",
        direct_set(&state).is_some(),
    ) && !conversation_muted_on(conn, principal, id, &state).await?)
}

pub(crate) const EVENTS_DDL: &str = "CREATE TABLE kernel_message_candidate_events(seq INTEGER PRIMARY KEY,event_key TEXT NOT NULL UNIQUE,principal_id TEXT NOT NULL,candidate_id TEXT NOT NULL,state TEXT NOT NULL CHECK(json_valid(state)))";
pub(crate) const FRONTIER_DDL: &str = "CREATE TABLE kernel_message_candidate_import_frontiers(message_id TEXT PRIMARY KEY,source_seq INTEGER NOT NULL)";
pub(crate) const DDL: &str = "CREATE TABLE kernel_message_candidates(candidate_id TEXT PRIMARY KEY,principal_id TEXT NOT NULL,message_id TEXT NOT NULL,state TEXT NOT NULL CHECK(json_valid(state)),event_seq INTEGER NOT NULL)";
pub(crate) const INDEX: &str = "CREATE INDEX idx_kernel_message_candidates_recipient ON kernel_message_candidates(principal_id,event_seq)";
pub(crate) const EVENT_INDEX: &str = "CREATE INDEX idx_kernel_message_candidate_events_recipient ON kernel_message_candidate_events(principal_id,seq)";

// Keep ordinary edits out of the wake-time authority scan. Conditional types
// retain only potentially relevant rows; generic removals need their prior link
// witness at read time and therefore remain candidates until then.
pub(crate) const REALTIME_AUTHORITY_INDEX: &str = r#"CREATE INDEX idx_kernel_realtime_authority ON content_events(type,seq) WHERE (
 type IN ('kernel.root_admin_bootstrapped.v1',
 'kernel.home_created_for.v1','kernel.home_policy_replaced.v1',
 'kernel.hosted_membership.v1','kernel.hosted_offboarding.v1',
 'kernel.import_hosted_accounts.v1','kernel.import_member_policy.v1',
 'kernel.import_home.v1','kernel.import_home_delta.v1','kernel.import_home_policy.v1',
 'kernel.import_state.v1','kernel.import_state_delta.v1','kernel.import_removed.v1',
 'kernel.record_deleted.v1','kernel.record_rebound.v1',
 'kernel.record_rehomed.v1','kernel.record_rehomed.v2',
 'kernel.generic_link_removed.v1','kernel.generic_link_removal_imported.v1')
 OR (type='kernel.home_created.v1' AND json_type(payload,'$.entries')='array')
 OR (type='kernel.identity_binding_added.v1' AND json_extract(payload,'$.binding.system')='native-principal')
 OR (type IN ('kernel.record_revised.v1','kernel.record_revised.v2') AND
   (json_type(payload,'$.fields.v1_type') IS NOT NULL OR json_type(payload,'$.fields.v1_kind') IS NOT NULL))
 OR (type IN ('kernel.generic_link_added.v1','kernel.generic_link_imported.v1','kernel.link_added.v1','kernel.link_removed.v1')
   AND json_extract(payload,'$.relationship')='part_of')
)"#;

pub(crate) async fn ensure_schema(conn: &mut SqliteConnection) -> Result<()> {
    for ddl in [
        PREFERENCES_DDL,
        EVENTS_DDL,
        DDL,
        INDEX,
        EVENT_INDEX,
        FRONTIER_DDL,
        REALTIME_AUTHORITY_INDEX,
    ] {
        sqlx::query(
            &ddl.replacen("CREATE TABLE", "CREATE TABLE IF NOT EXISTS", 1)
                .replacen("CREATE INDEX", "CREATE INDEX IF NOT EXISTS", 1),
        )
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

async fn put(
    conn: &mut SqliteConnection,
    key: &str,
    principal: &str,
    candidate: &Value,
) -> Result<()> {
    let id = candidate["candidate_id"]
        .as_str()
        .ok_or_else(|| Error::engine("candidate identity missing"))?;
    let message = candidate["message_id"]
        .as_str()
        .ok_or_else(|| Error::engine("candidate message missing"))?;
    let identity: Option<(String, String)> = sqlx::query_as(
        "SELECT principal_id,message_id FROM kernel_message_candidates WHERE candidate_id=?",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    if identity.is_some_and(|(p, m)| p != principal || m != message) {
        return Err(Error::conflict("notification candidate identity collision"));
    }
    if sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM kernel_message_candidate_events WHERE event_key=?)",
    )
    .bind(key)
    .fetch_one(&mut *conn)
    .await?
    {
        return Ok(());
    }
    // An existing v1 installation may retain its source cursor. Keep the new
    // sequence above imported source frontiers as well as native transitions.
    let floor = candidate["source_frontier"].as_i64().unwrap_or(0);
    let seq: i64 = sqlx::query_scalar("INSERT INTO kernel_message_candidate_events SELECT MAX(COALESCE(MAX(seq),0)+1,?,COALESCE((SELECT MAX(source_seq)+1 FROM kernel_message_candidate_import_frontiers),0)),?,?,?,? FROM kernel_message_candidate_events RETURNING seq")
        .bind(floor).bind(key).bind(principal).bind(id).bind(serde_json::to_string(candidate)?).fetch_one(&mut *conn).await?;
    sqlx::query("INSERT INTO kernel_message_candidates VALUES(?,?,?,?,?) ON CONFLICT(candidate_id) DO UPDATE SET state=excluded.state,event_seq=excluded.event_seq")
        .bind(id).bind(principal).bind(candidate["message_id"].as_str()).bind(serde_json::to_string(candidate)?).bind(seq).execute(conn).await?;
    Ok(())
}

fn truth(v: &Value) -> bool {
    v == true || v == 1
}
fn lane<'a>(state: &'a MessageState, principal: &str, name: &str) -> &'a Value {
    state
        .private
        .get(principal)
        .and_then(|lanes| lanes.get(name))
        .unwrap_or(&Value::Null)
}

async fn propose(
    conn: &mut SqliteConnection,
    event: &EventRow,
    principal: &str,
    reason: &str,
    not_before: Option<&str>,
    policy: &str,
    evaluator: &str,
) -> Result<()> {
    let id = Uuid::new_v5(
        &Uuid::NAMESPACE_OID,
        format!(
            "native.kernel.notification:{}:{principal}:{reason}",
            event.id
        )
        .as_bytes(),
    )
    .to_string();
    let candidate = json!({"candidate_id":id,"message_id":event.record_id,"reason":reason,"priority":"routine","not_before":not_before,"redaction_class":"metadata_only","evaluator_kind":evaluator,"policy_version":policy,"status":"effective","created_at":event.created_at,"source_event_type":event.event_type,"source_event_id":event.id,"assurance":"native_live"});
    put(
        conn,
        &format!("{}:{id}:proposed", event.id),
        principal,
        &candidate,
    )
    .await
}

async fn withdraw(
    conn: &mut SqliteConnection,
    event: &EventRow,
    principal: &str,
    reason: Option<&str>,
) -> Result<()> {
    let rows: Vec<String> = sqlx::query_scalar("SELECT state FROM kernel_message_candidates WHERE principal_id=? AND message_id=? AND json_extract(state,'$.status')='effective' AND (? IS NULL OR json_extract(state,'$.reason')=?) ORDER BY candidate_id")
        .bind(principal).bind(&event.record_id).bind(reason).bind(reason).fetch_all(&mut *conn).await?;
    for raw in rows {
        let mut candidate: Value = serde_json::from_str(&raw)?;
        candidate["status"] = json!("withdrawn");
        let id = candidate["candidate_id"].as_str().unwrap();
        put(
            conn,
            &format!("{}:{id}:withdrawn", event.id),
            principal,
            &candidate,
        )
        .await?;
    }
    Ok(())
}

/// v1 record.deleted withdraws every live candidate for its Message in the
/// same transaction. Reuse the normal withdrawal fold and deterministic IDs.
pub(crate) async fn deleted_on(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let principals: Vec<String> = sqlx::query_scalar("SELECT DISTINCT principal_id FROM kernel_message_candidates WHERE message_id=? AND json_extract(state,'$.status')='effective' ORDER BY principal_id")
        .bind(&event.record_id).fetch_all(&mut *conn).await?;
    for principal in principals {
        withdraw(conn, event, &principal, None).await?;
    }
    Ok(())
}

/// Called only by accepted Message projectors, including retained-event replay.
pub(crate) async fn project(
    conn: &mut SqliteConnection,
    event: &EventRow,
    before: Option<&MessageState>,
    state: &MessageState,
) -> Result<()> {
    if before.is_none() {
        let people: Vec<(String, String)> = sqlx::query_as(
            "SELECT person_id,principal_id FROM kernel_message_people ORDER BY principal_id",
        )
        .fetch_all(&mut *conn)
        .await?;
        for (person, principal) in people {
            let addressed = state.addressed_to.contains(&person);
            let mentioned = state.mentions.iter().any(|m| {
                m["target_kind"] == "principal"
                    && m["target_id"] == person
                    && truth(&m["effective"])
            });
            if !addressed && !mentioned {
                continue;
            }
            if addressed && state.expectation.as_deref().is_some_and(|v| v != "none") {
                propose(
                    conn,
                    event,
                    &principal,
                    "human_obligation",
                    None,
                    "messaging-awareness-v1",
                    "portable_default",
                )
                .await?;
            }
            if mentioned {
                propose(
                    conn,
                    event,
                    &principal,
                    "principal_mention",
                    None,
                    "messaging-awareness-v1",
                    "portable_default",
                )
                .await?;
            }
        }
        routine_arrivals(conn, event, state).await?;
        return Ok(());
    }
    let before = before.unwrap();
    let principal = event.actor.as_deref().unwrap_or_default();
    let human = lane(state, principal, "human");
    if lane(before, principal, "human") != human
        && matches!(human["stage"].as_str(), Some("opened" | "acknowledged"))
    {
        withdraw(conn, event, principal, None).await?;
    }
    // An acknowledgement closes the acknowledger's obligation, like v1's
    // satisfied/closed routing. Only the obligation goes; a mention clears on open.
    if state.acknowledgements.contains_key(principal)
        && !before.acknowledgements.contains_key(principal)
    {
        withdraw(conn, event, principal, Some("human_obligation")).await?;
    }
    let pref = lane(state, principal, "preference");
    let old = lane(before, principal, "preference");
    // Every accepted archive action withdraws every kind, as v1's does, even
    // on an already archived message: a candidate proposed since (a snooze
    // reminder) goes with it. Restoring proposes nothing back.
    if old != pref && pref["last_action"].as_str() == Some("archive") {
        withdraw(conn, event, principal, None).await?;
    }
    if old != pref
        && (old["snoozed_until"] != pref["snoozed_until"]
            || matches!(
                pref["last_action"].as_str(),
                Some("snooze" | "clear_snooze")
            ))
    {
        let until = pref["snoozed_until"].as_str();
        withdraw(
            conn,
            event,
            principal,
            if until.is_some() {
                None
            } else {
                Some("snooze_due")
            },
        )
        .await?;
        if let Some(until) = until {
            propose(
                conn,
                event,
                principal,
                "snooze_due",
                Some(until),
                "explicit-snooze-v1",
                "recipient_policy",
            )
            .await?;
        }
    }
    let route = lane(state, principal, "routing");
    let old = lane(before, principal, "routing");
    if route != old {
        let open = |v: &Value| v["obligation_state"] == "open" && v["executor_route"] == "human";
        if !open(route) {
            withdraw(conn, event, principal, Some("human_obligation")).await?;
        } else if !open(old) && !matches!(human["stage"].as_str(), Some("opened" | "acknowledged"))
        {
            let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_message_candidates WHERE principal_id=? AND message_id=? AND json_extract(state,'$.reason')='human_obligation' AND json_extract(state,'$.status')='effective')").bind(principal).bind(&event.record_id).fetch_one(&mut *conn).await?;
            if !exists {
                propose(
                    conn,
                    event,
                    principal,
                    "human_obligation",
                    None,
                    route["policy_version"]
                        .as_str()
                        .unwrap_or("explicit-human-route-v1"),
                    "recipient_policy",
                )
                .await?;
            }
        }
    }
    Ok(())
}

/// D10: source candidates/frontiers are retained evidence, never new delivery.
pub(crate) async fn import_history(
    conn: &mut SqliteConnection,
    id: &str,
    state: &MessageState,
    seq: i64,
) -> Result<()> {
    let floor = state
        .source
        .get("notification_frontier")
        .into_iter()
        .flatten()
        .filter_map(|r| r["seq"].as_i64())
        .max()
        .unwrap_or(0);
    sqlx::query("INSERT INTO kernel_message_candidate_import_frontiers VALUES(?,?) ON CONFLICT(message_id) DO UPDATE SET source_seq=MAX(source_seq,excluded.source_seq)").bind(id).bind(floor).execute(&mut *conn).await?;
    for row in state
        .source
        .get("notification_candidates")
        .into_iter()
        .flatten()
    {
        let Some(account) = row["recipient_account_id"].as_str() else {
            return Err(Error::engine("invalid imported notification recipient"));
        };
        let principal: Option<String> = sqlx::query_scalar(
            "SELECT principal_id FROM kernel_principals WHERE auth_binding=? AND kind='account'",
        )
        .bind(account)
        .fetch_optional(&mut *conn)
        .await?;
        let Some(principal) = principal else {
            continue;
        }; // Raw unresolved evidence remains sealed in the snapshot.
        let mut candidate = row.clone();
        candidate["message_id"] = json!(id);
        candidate["source_status"] = candidate["status"].clone();
        candidate["status"] = json!("suppressed");
        candidate["assurance"] = json!("imported_historical");
        candidate["delivery_eligible"] = json!(false);
        candidate["source_frontier"] = json!(state
            .source
            .get("notification_candidate_events")
            .into_iter()
            .flatten()
            .filter_map(|r| r["seq"].as_i64())
            .max()
            .unwrap_or(0)
            .max(row["candidate_event_seq"].as_i64().unwrap_or(0)));
        let cid = candidate["candidate_id"]
            .as_str()
            .ok_or_else(|| Error::engine("invalid imported notification identity"))?;
        put(conn, &format!("import:{seq}:{cid}"), &principal, &candidate).await?;
    }
    Ok(())
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn head_on(conn: &mut SqliteConnection, principal: &str) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COALESCE(MAX(seq),0) FROM kernel_message_candidate_events WHERE principal_id=?",
    )
    .bind(principal)
    .fetch_one(conn)
    .await?)
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn rows_on(
    conn: &mut SqliteConnection,
    principal: &str,
    after: i64,
    limit: i64,
) -> Result<(Vec<Value>, i64)> {
    let rows:Vec<(String,String,i64)>=sqlx::query_as("SELECT message_id,state,event_seq FROM kernel_message_candidates WHERE principal_id=? AND event_seq>? ORDER BY event_seq LIMIT ?").bind(principal).bind(after).bind(limit).fetch_all(&mut *conn).await?;
    let mut values = Vec::new();
    let mut scanned = after;
    for (id, raw, seq) in rows {
        scanned = scanned.max(seq);
        if !kernel_effective_capability_on(conn, principal, &id)
            .await?
            .allows(Capability::View)
        {
            continue;
        }
        let mut value: Value = serde_json::from_str(&raw)?;
        // Preserve withdrawal rows for consumers while withholding an arrival
        // that current preference/mute no longer permits.
        if value["status"] == "effective" && !current_allows(conn, principal, &value).await? {
            continue;
        }
        value["seq"] = json!(seq);
        values.push(value);
    }
    Ok((values, scanned))
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn count_on(
    conn: &mut SqliteConnection,
    principal: &str,
    id: &str,
) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM kernel_message_candidates WHERE principal_id=? AND message_id=? AND json_extract(state,'$.status')='effective'").bind(principal).bind(id).fetch_one(conn).await?)
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn is_v2(db: &Db) -> Result<bool> {
    is_v2_pool(db.pool()).await
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn is_v2_pool(pool: &sqlx::SqlitePool) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='kernel_messages' AND type='table') AND NOT EXISTS(SELECT 1 FROM sqlite_master WHERE name='records' AND type='table')").fetch_one(pool).await?)
}

/// Realtime's grant fence is separate from the broader snapshot cache fence
/// (v1: realtime::inbox_vector_on / authorization_grant_revision). In
/// particular ordinary births, edits, reactions, runs and private message
/// preferences cannot retire every live app frame. Select immutable authority
/// events, so the revision remains monotone across rebuilds and later moves.
/// Deletion, rehoming and derived-bearer changes conservatively invalidate:
/// they can revoke a derived record's View even without replacing a policy.
#[cfg(feature = "v2-kernel-probe")]
const REALTIME_AUTHORITY_EVENT: &str = r#"(
 e.type IN ('kernel.root_admin_bootstrapped.v1',
 'kernel.home_created_for.v1','kernel.home_policy_replaced.v1',
 'kernel.hosted_membership.v1','kernel.hosted_offboarding.v1',
 'kernel.import_hosted_accounts.v1','kernel.import_member_policy.v1',
 'kernel.import_home.v1','kernel.import_home_delta.v1','kernel.import_home_policy.v1',
 'kernel.import_state.v1','kernel.import_state_delta.v1','kernel.import_removed.v1',
 'kernel.record_deleted.v1','kernel.record_rebound.v1',
 'kernel.record_rehomed.v1','kernel.record_rehomed.v2')
 OR (e.type='kernel.home_created.v1' AND json_type(e.payload,'$.entries')='array')
 OR (e.type='kernel.identity_binding_added.v1' AND json_extract(e.payload,'$.binding.system')='native-principal')
 OR (e.type IN ('kernel.record_revised.v1','kernel.record_revised.v2') AND EXISTS (
   SELECT 1 FROM json_each(e.payload,'$.fields') f WHERE f.key IN ('v1_type','v1_kind')))
 OR (e.type IN ('kernel.generic_link_added.v1','kernel.generic_link_imported.v1','kernel.link_added.v1','kernel.link_removed.v1')
   AND json_extract(e.payload,'$.relationship')='part_of')
 OR (e.type IN ('kernel.generic_link_removed.v1','kernel.generic_link_removal_imported.v1') AND EXISTS (
   SELECT 1 FROM main.content_events added WHERE added.seq<e.seq
   AND added.type IN ('kernel.generic_link_added.v1','kernel.generic_link_imported.v1')
   AND json_extract(added.payload,'$.link_id')=json_extract(e.payload,'$.link_id')
   AND json_extract(added.payload,'$.relationship')='part_of'))
)"#;

/// App consent changes deliberately do not move this fence, matching v1:
/// current consent is enforced on every app request and subscription check.
/// Body-free durable wakeup fence. The host still owns fan-out and admission.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn vector(
    pool: &sqlx::SqlitePool,
) -> Result<crate::realtime::InboxInvalidationVector> {
    let mut tx = pool.begin().await?;
    let content = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(&mut *tx)
        .await?;
    let awareness = sqlx::query_scalar(
        "SELECT COALESCE(MAX(seq),0) FROM content_events WHERE type IN ('kernel.message_state.v1','kernel.notification_preference_set.v1')",
    )
    .fetch_one(&mut *tx)
    .await?;
    let candidates=sqlx::query_scalar("SELECT MAX(COALESCE((SELECT MAX(seq) FROM kernel_message_candidate_events),0),COALESCE((SELECT MAX(source_seq) FROM kernel_message_candidate_import_frontiers),0))").fetch_one(&mut *tx).await?;
    let control = sqlx::query_scalar(
        "SELECT COALESCE(MAX(seq),0) FROM content_events WHERE type LIKE 'kernel.run%'",
    )
    .fetch_one(&mut *tx)
    .await?;
    // Reuse the partial-index predicate, but keep older v2 files usable when
    // the optional index is absent. seq + 0 suppresses MAX(rowid)'s backwards
    // full-log shortcut so SQLite can choose the partial index when present.
    let authority_candidates = REALTIME_AUTHORITY_INDEX.split_once(" WHERE ").unwrap().1;
    let authorization = sqlx::query_scalar(&format!(
        "SELECT COALESCE(MAX(e.seq + 0),0) FROM content_events e WHERE {authority_candidates} AND {REALTIME_AUTHORITY_EVENT}"
    ))
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(crate::realtime::InboxInvalidationVector {
        content,
        awareness,
        candidates,
        control,
        authorization,
    })
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn addressed(
    pool: &sqlx::SqlitePool,
    account: &str,
    prev: &crate::realtime::InboxInvalidationVector,
    cur: &crate::realtime::InboxInvalidationVector,
) -> Result<bool> {
    if account.starts_with("host:") {
        return Ok(false);
    }
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_message_candidate_events e JOIN kernel_principals p ON p.principal_id=e.principal_id WHERE p.auth_binding=?1 AND e.seq>?2 AND e.seq<=?3) OR EXISTS(SELECT 1 FROM content_events e JOIN kernel_principals p ON p.principal_id=e.actor WHERE p.auth_binding=?1 AND e.type IN ('kernel.message_state.v1','kernel.notification_preference_set.v1') AND e.seq>?4 AND e.seq<=?5)").bind(account).bind(prev.candidates).bind(cur.candidates).bind(prev.awareness).bind(cur.awareness).fetch_one(pool).await?)
}

#[cfg(feature = "v2-kernel-probe")]
async fn recipient(db: &Db, account: &str) -> Result<Option<String>> {
    Ok(resolve_caller_principal_by_binding(db, account)
        .await?
        .map(|v| v.0))
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn harvest(
    db: &Db,
    account: &str,
    after: i64,
    limit: i64,
) -> Result<crate::awareness::HostNotificationHarvest> {
    if after < 0 || !(1..=500).contains(&limit) {
        return Err(Error::engine(
            "harvest limit must be 1..=500; cursor must be nonnegative",
        ));
    }
    let Some(principal) = recipient(db, account).await? else {
        return Ok(crate::awareness::HostNotificationHarvest {
            scanned_through: after,
            candidates: vec![],
        });
    };
    let mut tx = db.write_pool().begin().await?;
    let (rows, scanned_through) = rows_on(&mut tx, &principal, after, limit).await?;
    let mut candidates = Vec::new();
    for row in rows {
        if row["status"] != "effective" || row["assurance"] != "native_live" {
            continue;
        }
        let state = messaging::on(&mut tx, row["message_id"].as_str().unwrap_or_default())
            .await?
            .ok_or_else(|| Error::engine("candidate message missing"))?;
        candidates.push(crate::awareness::HostNotificationCandidate {
            candidate_id: row["candidate_id"].as_str().unwrap().into(),
            reason: row["reason"].as_str().unwrap().into(),
            priority: row["priority"].as_str().unwrap().into(),
            redaction_class: row["redaction_class"].as_str().unwrap().into(),
            evaluator_kind: row["evaluator_kind"].as_str().unwrap().into(),
            policy_version: row["policy_version"].as_str().unwrap().into(),
            muted: truth(&lane(&state, &principal, "preference")["muted"]),
        });
    }
    Ok(crate::awareness::HostNotificationHarvest {
        scanned_through,
        candidates,
    })
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn revalidate(
    db: &Db,
    id: &str,
    account: &str,
) -> Result<Option<crate::awareness::HostNotificationRevalidation>> {
    let Some(principal) = recipient(db, account).await? else {
        return Ok(None);
    };
    let mut tx = db.write_pool().begin().await?;
    let raw: Option<String> = sqlx::query_scalar(
        "SELECT state FROM kernel_message_candidates WHERE candidate_id=? AND principal_id=?",
    )
    .bind(id)
    .bind(&principal)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let row: Value = serde_json::from_str(&raw)?;
    let message_id = row["message_id"].as_str().unwrap_or_default().to_owned();
    let visible = kernel_effective_capability_on(&mut tx, &principal, &message_id)
        .await?
        .allows(Capability::View);
    let state = messaging::on(&mut tx, &message_id)
        .await?
        .unwrap_or_default();
    Ok(Some(crate::awareness::HostNotificationRevalidation {
        message_id,
        not_before: row["not_before"].as_str().map(str::to_owned),
        priority: row["priority"].as_str().unwrap_or("routine").into(),
        evaluator_kind: row["evaluator_kind"]
            .as_str()
            .unwrap_or("portable_default")
            .into(),
        policy_version: row["policy_version"].as_str().unwrap_or_default().into(),
        effective_viewable_unmuted: visible
            && row["status"] == "effective"
            && row["assurance"] == "native_live"
            && current_allows(&mut tx, &principal, &row).await?
            && !truth(&lane(&state, &principal, "preference")["muted"]),
    }))
}

/// v1 awareness.rs:3478: close only human-obligation candidates, for each
/// recipient whose obligation the mark closes. Undo never redelivers.
pub(crate) async fn relevance_on(
    conn: &mut SqliteConnection,
    event: &EventRow,
    message: &str,
) -> Result<()> {
    let Some(state) = messaging::on(conn, message).await? else {
        return Ok(());
    };
    let recipients: Vec<String> = sqlx::query_scalar("SELECT DISTINCT principal_id FROM kernel_message_candidates WHERE message_id=? AND json_extract(state,'$.reason')='human_obligation' AND json_extract(state,'$.status')='effective' ORDER BY principal_id")
        .bind(message).fetch_all(&mut *conn).await?;
    let mut source = event.clone();
    source.record_id = message.into();
    for actor in recipients {
        let route = lane(&state, &actor, "routing");
        let closed = if let Some(routed) = route["obligation_state"].as_str() {
            routed != "open"
        } else {
            messaging::expectation_value(conn, &actor, message, &state).await?["state"]
                == "satisfied"
        };
        if closed {
            withdraw(conn, &source, &actor, Some("human_obligation")).await?;
        }
    }
    Ok(())
}
