//! History and change-window reads over the authoritative content log. The
//! internal version helper remains for the diff app, while public historical
//! state is exposed uniformly as `as_of` on structured read tools.

use std::collections::{BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;

use crate::authorization::Capability;
use crate::db::{apply_schema, open_database, Db};
use crate::error::{Error, Result};
use crate::events::EventRow;
use crate::events::OccurrenceBoundPayload;
use crate::query::lens::{self, AsOfSelector, ContentSeqSelector, ReadLens};
use crate::query::{events, read};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{can_record, parse_args, require_record};

/// Default page size for `get_history` (the reader caps at its own MAX_PAGE).
const DEFAULT_PAGE: i64 = 100;

const EVENT_FAMILIES: [&str; 8] = [
    "annotations",
    "created",
    "deleted",
    "facets",
    "impacts",
    "links",
    "moved",
    "updated",
];

/// Ceiling on distinct `accounts` values in one `whats_changed` call. The
/// account list becomes one `?` placeholder per value in the SQL window's
/// `actor IN (...)` predicate, so an unbounded caller-controlled list risks
/// SQLite's bind-variable limit and turns one read into a statement-shape
/// denial of service. Deduplication happens first (`normalize_string_filter`
/// collects into a set), so this bounds distinct values, not raw array
/// length.
const MAX_WHATS_CHANGED_ACCOUNTS: usize = 1000;

const CREATED_RECORD_FIELDS: [&str; 10] = [
    "body",
    "home_id",
    "kind",
    "lifecycle",
    "maturity",
    "name",
    "owner_id",
    "persistence",
    "summary",
    "type",
];

const UPDATED_RECORD_FIELDS: [&str; 9] = [
    "body",
    "home_id",
    "kind",
    "lifecycle",
    "maturity",
    "name",
    "owner_id",
    "persistence",
    "summary",
];

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
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
struct WhatsChangedArgs {
    #[serde(
        default,
        rename = "after_local_seq",
        alias = "after_seq",
        deserialize_with = "deserialize_present"
    )]
    after_seq: Option<i64>,
    #[serde(
        default,
        rename = "through_local_seq",
        alias = "through_seq",
        deserialize_with = "deserialize_present"
    )]
    through_seq: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_present")]
    limit: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_present")]
    scope_record_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present")]
    actor_scope: Option<ActorScope>,
    #[serde(default, deserialize_with = "deserialize_present")]
    accounts: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_present")]
    for_run: Option<String>,
    #[serde(default)]
    include_child_runs: bool,
    #[serde(default, deserialize_with = "deserialize_present")]
    event_families: Option<Vec<String>>,
    #[serde(default)]
    order: HistoryOrder,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct ChangeGroupKey {
    record_id: String,
    actor: Option<String>,
    run_key: Option<String>,
}

#[derive(Debug)]
struct ChangeGroup {
    key: ChangeGroupKey,
    first_seq: i64,
    last_seq: i64,
    first_event_at: String,
    last_event_at: String,
    event_count: i64,
    event_types: BTreeSet<String>,
    event_families: BTreeSet<String>,
    changed_fields: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetHistoryArgs {
    /// One record's stream; omit for the whole log.
    record_id: Option<String>,
    /// Run query selector. This cannot be named `run_key`: the registry lifts
    /// that reserved argument out as caller correlation before serde sees it.
    #[serde(default, deserialize_with = "deserialize_present")]
    for_run: Option<String>,
    #[serde(default)]
    include_child_runs: bool,
    #[serde(rename = "after_local_seq", alias = "after_seq")]
    after_seq: Option<i64>,
    limit: Option<i64>,
    #[serde(default)]
    order: HistoryOrder,
    #[serde(default)]
    detail: HistoryDetail,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HistoryDetail {
    #[default]
    Metadata,
    Full,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum HistoryOrder {
    #[default]
    OldestFirst,
    NewestFirst,
}

impl HistoryOrder {
    fn event_order(self) -> events::EventOrder {
        match self {
            Self::OldestFirst => events::EventOrder::OldestFirst,
            Self::NewestFirst => events::EventOrder::NewestFirst,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetRunActivityArgs {
    /// Query selector, deliberately distinct from the caller-correlation
    /// `run_key` that the registry removes before handler deserialization.
    #[serde(default, deserialize_with = "deserialize_present")]
    for_run: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present")]
    include_child_runs: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_present")]
    cursor: Option<RunDiscoveryCursor>,
    limit: Option<i64>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunDiscoveryCursor {
    observed_at: String,
    open_rank: i64,
    sort_at: String,
    activity_id: String,
}

const RUN_DISCOVERY_DEFAULT_LIMIT: i64 = 20;
const RUN_DISCOVERY_MAX_LIMIT: i64 = 50;
const RUN_DISCOVERY_RECENT_HOURS: i64 = 24;

/// Unlike serde's ordinary `Option<T>`, reject an explicit JSON null.
/// Omission is supplied by `#[serde(default)]`; every present field must
/// deserialize to its concrete value type.
fn deserialize_present<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// An event row rendered for tool output: `payload` is parsed JSON, not the
/// stored text (handlers return structured data; a JSON-in-a-string field
/// would push parsing onto every caller).
pub(super) fn event_to_value(event: &EventRow, actor_names: &HashMap<String, String>) -> Value {
    let payload = event
        .payload
        .as_deref()
        .map(|raw| serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_string())));
    json!({
        "local_seq": event.local_seq,
        "id": event.id,
        "record_id": event.record_id,
        "type": event.event_type,
        "payload": payload,
        "actor": event.actor,
        "actor_name": event.actor.as_ref().map(|actor| {
            actor_names.get(actor).cloned().unwrap_or_else(|| actor.clone())
        }),
        "run_key": event.run_key,
        "parent_key": event.parent_key,
        "intent": event.intent,
        "created_at": event.created_at,
        "causal_envelope": event.causal_envelope,
    })
}

/// Shape one already-authorized, already-redacted event for `get_history`.
///
/// Adapters build the same full event object first and call this helper only
/// after their own visibility and redaction gates. Keeping the lossy projection
/// here makes metadata disclosure identical across engines without changing the
/// full event representation shared by event-context and App tools.
pub(crate) fn shape_history_event(mut event: Value, detail: HistoryDetail) -> Value {
    // A canvas batch's payload is the whole scene delta, and generic history
    // has no way to redact record cards inside it. Both detail levels see the
    // same lossy summary; the ops are reachable only through
    // `read_canvas.changes`, which redacts as the caller.
    if event.get("type").and_then(Value::as_str) == Some(crate::canvas::CANVAS_BATCH_EVENT_TYPE) {
        let summary = crate::canvas::history_summary(&event);
        if let Some(object) = event.as_object_mut() {
            object.insert("payload".into(), summary);
        }
    }
    if matches!(detail, HistoryDetail::Full) {
        return event;
    }
    let Some(object) = event.as_object_mut() else {
        return event;
    };
    let payload = object.remove("payload").unwrap_or(Value::Null);
    let payload_omitted = !payload.is_null();
    let payload_json_utf8_bytes = payload_omitted.then(|| {
        serde_json::to_vec(&payload)
            .expect("serde_json::Value always serializes")
            .len() as u64
    });
    let reason = payload
        .get("reason")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let event_type = object
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let changed_fields = metadata_changed_fields(event_type, &payload);
    object.insert("payload_omitted".into(), json!(payload_omitted));
    object.insert(
        "payload_json_utf8_bytes".into(),
        payload_json_utf8_bytes.map_or(Value::Null, Value::from),
    );
    object.insert("changed_fields".into(), json!(changed_fields));
    if let Some(reason) = reason {
        object.insert("reason".into(), Value::String(reason));
    }
    event
}

pub(crate) fn history_representation(detail: HistoryDetail) -> Value {
    match detail {
        HistoryDetail::Metadata => json!({
            "detail": "metadata",
            "payloads": "omitted",
            "omitted_field": "events[].payload",
            "full_detail": { "detail": "full" },
            "payload_size": {
                "field": "payload_json_utf8_bytes",
                "unit": "bytes",
                "encoding": "UTF-8 JSON"
            }
        }),
        HistoryDetail::Full => json!({
            "detail": "full",
            "payloads": "included"
        }),
    }
}

fn metadata_changed_fields(event_type: &str, payload: &Value) -> Vec<String> {
    changed_fields_for_payload(event_type, payload)
        .into_iter()
        .collect()
}

fn changed_fields_for_payload(event_type: &str, payload: &Value) -> BTreeSet<String> {
    let mut fields = BTreeSet::new();
    let allowed = match event_type {
        "record.created" => Some(CREATED_RECORD_FIELDS.as_slice()),
        "record.updated" | "receipt.committed.v1" => Some(UPDATED_RECORD_FIELDS.as_slice()),
        _ => None,
    };
    if let Some(allowed) = allowed {
        let object = payload.as_object();
        for field in allowed {
            if object.is_some_and(|payload| payload.contains_key(*field)) {
                fields.insert((*field).to_string());
            }
        }
        return fields;
    }
    if event_type == "record.type_corrected.v1" {
        fields.insert("kind".into());
        fields.insert("type".into());
        return fields;
    }
    if matches!(event_type, "facet.set" | "facet.unset") {
        if let Some(key) = payload.get("key").and_then(Value::as_str) {
            fields.insert(format!("facet:{key}"));
        }
    }
    fields
}

/// The `person` record an account token is bound to, and the display name it
/// carries.
///
/// Bylines resolve through this record on every read rather than storing a name
/// inline, so renaming the person propagates retroactively to everything they
/// have ever touched.
const ACTOR_PERSON_QUERY: &str = "SELECT person.id, person.name
   FROM bindings account
   JOIN records person ON person.id = account.record_id
  WHERE account.system = 'account' AND account.identifier = ?
  LIMIT 1";

/// Memoizes [`crate::authorization::actor_disclosable_with`] across one read.
///
/// The rule itself lives in `authorization` so that every engine's history
/// reader shares one decision point. This type only caches it: a page of
/// history holds many events but few distinct actors, and without the cache a
/// thousand-event page would evaluate the same handful of person policies a
/// thousand times.
#[derive(Default)]
pub(super) struct ActorDisclosure {
    decided: HashMap<String, bool>,
}

impl ActorDisclosure {
    async fn visible(&mut self, db: &Db, caller: &Caller, actor: &str) -> Result<bool> {
        if let Some(decided) = self.decided.get(actor) {
            return Ok(*decided);
        }
        let mut snapshot = db.write_pool().begin().await?;
        let visible = self.visible_in(&mut snapshot, caller, actor).await;
        snapshot.rollback().await?;
        visible
    }

    async fn visible_in(
        &mut self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        caller: &Caller,
        actor: &str,
    ) -> Result<bool> {
        if let Some(decided) = self.decided.get(actor) {
            return Ok(*decided);
        }
        // The trusted-local boundary already bypasses redaction wholesale in the
        // callers below, so this only ever evaluates a real hosted principal.
        let mut state = crate::portable_sql::BorrowedSqliteStatementExecutor::new(tx);
        let visible = crate::authorization::actor_disclosable_with(
            &mut state,
            super::principal(caller),
            actor,
        )
        .await?;
        self.decided.insert(actor.to_string(), visible);
        Ok(visible)
    }
}

/// Apply the shared actor-disclosure rule and, when permitted, resolve the
/// actor's current person name inside the caller's existing snapshot.
///
/// The actor token remains useful when a disclosable actor has no person
/// binding; callers must not manufacture a name for that state.
pub(super) async fn disclosed_actor_identity_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    actor: &str,
) -> Result<Option<(String, Option<String>)>> {
    let visible = if super::is_legacy_local(caller) {
        true
    } else {
        let mut state = crate::portable_sql::BorrowedSqliteStatementExecutor::new(tx);
        crate::authorization::actor_disclosable_with(&mut state, super::principal(caller), actor)
            .await?
    };
    if !visible {
        return Ok(None);
    }
    let display_name = sqlx::query(ACTOR_PERSON_QUERY)
        .bind(actor)
        .fetch_optional(&mut **tx)
        .await?
        .and_then(|row| row.try_get::<Option<String>, _>("name").ok().flatten());
    Ok(Some((actor.to_owned(), display_name)))
}

/// Name every actor still present on `events`.
///
/// This deliberately does no authorization of its own. `redact_event` is the
/// single gate on actor disclosure and every caller runs it over the same
/// events immediately beforehand, so an actor that survives to here has already
/// been cleared. Re-checking would duplicate the policy in a second place and
/// invite the two copies to drift.
pub(super) async fn resolve_actor_names(db: &Db, events: &[EventRow]) -> HashMap<String, String> {
    let actors: HashSet<_> = events
        .iter()
        .filter_map(|event| event.actor.clone())
        .collect();
    let mut names = HashMap::new();
    for actor in actors {
        let resolved = sqlx::query(ACTOR_PERSON_QUERY)
            .bind(&actor)
            .fetch_optional(db.write_pool())
            .await
            .ok()
            .flatten()
            .and_then(|row| row.try_get::<Option<String>, _>("name").ok().flatten())
            .unwrap_or_else(|| actor.clone());
        names.insert(actor, resolved);
    }
    names
}

/// Snapshot-scoped form of [`resolve_actor_names`], with the same reliance on
/// `redact_event_in` having already gated disclosure.
pub(super) async fn resolve_actor_names_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    events: &[EventRow],
) -> HashMap<String, String> {
    let actors: HashSet<_> = events
        .iter()
        .filter_map(|event| event.actor.clone())
        .collect();
    let mut names = HashMap::new();
    for actor in actors {
        let resolved = sqlx::query(ACTOR_PERSON_QUERY)
            .bind(&actor)
            .fetch_optional(&mut **tx)
            .await
            .ok()
            .flatten()
            .and_then(|row| row.try_get::<Option<String>, _>("name").ok().flatten())
            .unwrap_or_else(|| actor.clone());
        names.insert(actor, resolved);
    }
    names
}

#[cfg(test)]
mod whats_changed_bench;

pub(super) async fn redact_event(
    db: &Db,
    caller: &Caller,
    disclosure: &mut ActorDisclosure,
    event: &mut EventRow,
) -> Result<()> {
    // A canvas batch never travels through generic history whole; the ops
    // are reachable only through `read_canvas.changes`, which redacts.
    crate::canvas::summarise_event_row(event);
    if super::is_legacy_local(caller) {
        return Ok(());
    }
    // Identity used to be nulled here unconditionally for anyone but the actor,
    // while record references a few lines below were gated on `View`. Attribution
    // to a hidden actor is attribution nobody can act on, and knowing who acted
    // without knowing what they were trying to do does not let one member pick up
    // another's work — so the run and intent travel with the name, under that same
    // gate. Callers without `View` on the person see exactly what they saw before.
    let disclose_actor = match event.actor.as_deref() {
        Some(actor) => disclosure.visible(db, caller, actor).await?,
        None => false,
    };
    if !disclose_actor {
        event.actor = None;
        event.run_key = None;
        event.parent_key = None;
        event.intent = None;
    }
    let Some(raw) = event.payload.as_deref() else {
        return Ok(());
    };
    let Ok(mut payload) = serde_json::from_str::<Value>(raw) else {
        event.payload = None;
        return Ok(());
    };
    let claim_payload =
        payload.get("claimed_by_account").is_some() || payload.get("claimed_run_key").is_some();
    let claim_holder_visible = event.actor.as_deref() == Some(caller.credential())
        && event.run_key.as_deref() == caller.run_key();
    if claim_payload && !claim_holder_visible {
        event.run_key = None;
        event.parent_key = None;
        event.intent = None;
    }
    let mut stack = vec![&mut payload];
    while let Some(value) = stack.pop() {
        match value {
            Value::Object(object) => {
                for (key, child) in object.iter_mut() {
                    let identity_key =
                        matches!(key.as_str(), "actor" | "account_id" | "email" | "owner_id");
                    let record_key = key == "id"
                        || key.ends_with("_id")
                        || matches!(key.as_str(), "owner" | "home");
                    let claim_identity_key =
                        matches!(key.as_str(), "claimed_by_account" | "claimed_run_key");
                    if identity_key || (claim_identity_key && !claim_holder_visible) {
                        *child = Value::Null;
                    } else if record_key {
                        if let Some(id) = child.as_str() {
                            if !can_record(db, caller, id, Capability::View).await? {
                                *child = Value::Null;
                            }
                        }
                    } else {
                        stack.push(child);
                    }
                }
            }
            Value::Array(values) => stack.extend(values.iter_mut()),
            _ => {}
        }
    }
    event.payload = Some(serde_json::to_string(&payload)?);
    Ok(())
}

/// Semantic occurrence events carry exact selectors from an independently
/// protected artefact. Unit visibility alone therefore cannot make the event
/// visible. This check must run before page occupancy or aggregation.
pub(super) async fn event_is_visible(db: &Db, caller: &Caller, event: &EventRow) -> Result<bool> {
    if matches!(
        event.event_type.as_str(),
        "reconciliation.recorded.v1" | "unit.superseded.v1" | "receipt.dependency_audited.v1"
    ) {
        return Ok(false);
    }
    let acknowledgement = crate::query::acknowledgement_predicate("r");
    let hidden_acknowledgement: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM records r WHERE r.id=? AND {acknowledgement})"
    ))
    .bind(&event.record_id)
    .fetch_one(db.write_pool())
    .await?;
    if hidden_acknowledgement {
        return Ok(false);
    }
    if event.event_type != "occurrence.bound.v1" {
        return Ok(true);
    }
    let Some(raw) = event.payload.as_deref() else {
        return Ok(false);
    };
    let Ok(payload) = serde_json::from_str::<OccurrenceBoundPayload>(raw) else {
        return Ok(false);
    };
    can_record(
        db,
        caller,
        &payload.artefact_revision.subject_id,
        Capability::View,
    )
    .await
}

async fn event_is_visible_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    event: &EventRow,
) -> Result<bool> {
    if matches!(
        event.event_type.as_str(),
        "reconciliation.recorded.v1" | "unit.superseded.v1" | "receipt.dependency_audited.v1"
    ) {
        return Ok(false);
    }
    let acknowledgement = crate::query::acknowledgement_predicate("r");
    let hidden_acknowledgement: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM records r WHERE r.id=? AND {acknowledgement})"
    ))
    .bind(&event.record_id)
    .fetch_one(&mut **tx)
    .await?;
    if hidden_acknowledgement {
        return Ok(false);
    }
    if event.event_type != "occurrence.bound.v1" {
        return Ok(true);
    }
    let Some(raw) = event.payload.as_deref() else {
        return Ok(false);
    };
    let Ok(payload) = serde_json::from_str::<OccurrenceBoundPayload>(raw) else {
        return Ok(false);
    };
    super::can_record_in(
        tx,
        caller,
        &payload.artefact_revision.subject_id,
        Capability::View,
    )
    .await
}

pub(super) async fn redact_event_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    disclosure: &mut ActorDisclosure,
    event: &mut EventRow,
) -> Result<()> {
    crate::canvas::summarise_event_row(event);
    if super::is_legacy_local(caller) {
        return Ok(());
    }
    // See `redact_event`; this is the snapshot-scoped form of the same gate.
    let disclose_actor = match event.actor.as_deref() {
        Some(actor) => disclosure.visible_in(tx, caller, actor).await?,
        None => false,
    };
    if !disclose_actor {
        event.actor = None;
        event.run_key = None;
        event.parent_key = None;
        event.intent = None;
    }
    let Some(raw) = event.payload.as_deref() else {
        return Ok(());
    };
    let Ok(mut payload) = serde_json::from_str::<Value>(raw) else {
        event.payload = None;
        return Ok(());
    };
    let claim_payload =
        payload.get("claimed_by_account").is_some() || payload.get("claimed_run_key").is_some();
    let claim_holder_visible = event.actor.as_deref() == Some(caller.credential())
        && event.run_key.as_deref() == caller.run_key();
    if claim_payload && !claim_holder_visible {
        event.run_key = None;
        event.parent_key = None;
        event.intent = None;
    }
    let mut stack = vec![&mut payload];
    while let Some(value) = stack.pop() {
        match value {
            Value::Object(object) => {
                for (key, child) in object.iter_mut() {
                    let identity_key =
                        matches!(key.as_str(), "actor" | "account_id" | "email" | "owner_id");
                    let record_key = key == "id"
                        || key.ends_with("_id")
                        || matches!(key.as_str(), "owner" | "home");
                    let claim_identity_key =
                        matches!(key.as_str(), "claimed_by_account" | "claimed_run_key");
                    if identity_key || (claim_identity_key && !claim_holder_visible) {
                        *child = Value::Null;
                    } else if record_key {
                        if let Some(id) = child.as_str() {
                            if !super::can_record_in(tx, caller, id, Capability::View).await? {
                                *child = Value::Null;
                            }
                        }
                    } else {
                        stack.push(child);
                    }
                }
            }
            Value::Array(values) => stack.extend(values.iter_mut()),
            _ => {}
        }
    }
    event.payload = Some(serde_json::to_string(&payload)?);
    Ok(())
}

#[derive(Clone, Debug, Default)]
struct EventTimeIdentity {
    record_type: Option<String>,
    kind: Option<String>,
}

async fn event_time_identity(db: &Db, event: &EventRow) -> Result<EventTimeIdentity> {
    let row = sqlx::query(
        "SELECT
                (SELECT CASE WHEN type='record.type_corrected.v1'
                                  THEN json_extract(payload, '$.to.type')
                                  ELSE json_extract(payload, '$.type') END
                   FROM content_events
                  WHERE record_id = ? AND seq <= ?
                    AND type IN ('record.created','record.type_corrected.v1')
                  ORDER BY seq DESC LIMIT 1) AS record_type,
                (SELECT CASE WHEN type='record.type_corrected.v1'
                                  THEN json_extract(payload, '$.to.kind')
                                  ELSE json_extract(payload, '$.kind') END
                   FROM content_events
                  WHERE record_id = ? AND seq <= ?
                    AND type IN ('record.created', 'record.updated', 'receipt.committed.v1',
                                 'record.type_corrected.v1')
                    AND (json_type(payload, '$.kind') = 'text'
                         OR json_type(payload, '$.to.kind') = 'text')
                  ORDER BY seq DESC LIMIT 1) AS kind",
    )
    .bind(&event.record_id)
    .bind(event.local_seq)
    .bind(&event.record_id)
    .bind(event.local_seq)
    .fetch_one(db.write_pool())
    .await?;
    Ok(EventTimeIdentity {
        record_type: row.try_get("record_type")?,
        kind: row.try_get("kind")?,
    })
}

fn is_impact_identity(identity: &EventTimeIdentity) -> bool {
    identity.record_type.as_deref() == Some("Outcome") && identity.kind.as_deref() == Some("impact")
}

/// Family membership that needs nothing but the row itself: the event type
/// plus payload-key presence. This evaluation is deliberately tolerant: a
/// missing or malformed payload classifies as if the payload were null, which
/// is exactly what the redaction below normalizes it to before the post-auth
/// evaluation sees it. That equivalence is what makes this safe to evaluate
/// before authorization — an unauthorized row with a corrupt payload is
/// rejected by authorization exactly as before, and can never fail the call
/// at parse time.
fn event_families_without_impact(event: &EventRow) -> Result<BTreeSet<String>> {
    // Tolerant by construction: never `?` on the payload parse. Redaction
    // normalizes an unparseable payload to `None`, and `None` parses here as
    // null, so both evaluations observe the same value.
    let payload: Value = event
        .payload
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or(Value::Null);
    let mut families = BTreeSet::new();
    match event.event_type.as_str() {
        "record.created" => {
            families.insert("created".into());
        }
        "record.updated" => {
            families.insert("updated".into());
            let moved = payload
                .as_object()
                .is_some_and(|payload| payload.contains_key("home_id"));
            if moved {
                families.insert("moved".into());
            }
        }
        "record.type_corrected.v1" => {
            families.insert("updated".into());
        }
        "record.deleted" => {
            families.insert("deleted".into());
        }
        "facet.set" | "facet.unset" => {
            families.insert("facets".into());
        }
        "link.added" | "link.removed" => {
            families.insert("links".into());
        }
        "annotation.target.set"
        | "annotation.target.removed"
        | "message.reaction.added.v1"
        | "message.reaction.removed.v1" => {
            families.insert("annotations".into());
        }
        // Kept explicit though the default below now says the same thing: these
        // four were classified deliberately, not left to fall through.
        "artifact.source_attested"
        | "unit.created.v1"
        | "unit.revision.recorded.v1"
        | "occurrence.bound.v1" => {
            families.insert("updated".into());
        }
        // Everything else is reported as `updated`: something happened to this
        // record, and the aggregate cannot say more than that about a type it
        // has no opinion on.
        //
        // This arm is deliberately open. `EVENT_TYPES` grows independently of
        // this match, and it grew past it: `message.send_evaluated.v1` was
        // added the day after this function, and a single such event in the
        // scanned window failed the WHOLE call — Home's two bands went dark in
        // production, on data that is durable, so every reload failed the same
        // way. Refusing to summarize an event the aggregate does not model is
        // not worth taking the surface down for. An event whose family really
        // matters earns an arm above; a `_` here is the honest default for the
        // rest, and `event_types` still reports the exact type either way.
        _ => {
            families.insert("updated".into());
        }
    }
    Ok(families)
}

fn event_families(event: &EventRow, is_impact: bool) -> Result<BTreeSet<String>> {
    let mut families = event_families_without_impact(event)?;
    if is_impact {
        families.insert("impacts".into());
    }
    Ok(families)
}

fn changed_fields(event: &EventRow) -> Result<BTreeSet<String>> {
    let payload = event
        .payload
        .as_deref()
        .map(serde_json::from_str::<Value>)
        .transpose()?
        .unwrap_or(Value::Null);
    if matches!(event.event_type.as_str(), "facet.set" | "facet.unset")
        && payload.get("key").and_then(Value::as_str).is_none()
    {
        return Err(Error::engine(format!(
            "whats_changed event {} ({}) has no facet key",
            event.id, event.event_type
        )));
    }
    Ok(changed_fields_for_payload(&event.event_type, &payload))
}

fn normalize_string_filter(
    name: &str,
    values: Option<Vec<String>>,
) -> Result<Option<BTreeSet<String>>> {
    let Some(values) = values else {
        return Ok(None);
    };
    if values.is_empty() {
        return Err(Error::engine(format!(
            "whats_changed {name} must not be an empty array"
        )));
    }
    Ok(Some(values.into_iter().collect()))
}

/// Normalize the `accounts` filter and cap its distinct values before they
/// can become SQL `IN` placeholders (see `MAX_WHATS_CHANGED_ACCOUNTS`).
/// Both traversals — production and the test-only legacy reference — parse
/// through here so validation cannot drift between them.
fn normalize_accounts(values: Option<Vec<String>>) -> Result<Option<BTreeSet<String>>> {
    let accounts = normalize_string_filter("accounts", values)?;
    if accounts
        .as_ref()
        .is_some_and(|selected| selected.len() > MAX_WHATS_CHANGED_ACCOUNTS)
    {
        return Err(Error::engine(format!(
            "whats_changed accounts must not exceed {MAX_WHATS_CHANGED_ACCOUNTS} values"
        )));
    }
    Ok(accounts)
}

fn normalize_event_families(values: Option<Vec<String>>) -> Result<Option<BTreeSet<String>>> {
    let values = normalize_string_filter("event_families", values)?;
    if let Some(values) = &values {
        for family in values {
            if !EVENT_FAMILIES.contains(&family.as_str()) {
                return Err(Error::engine(format!(
                    "whats_changed unknown event family '{family}'; expected one of {}",
                    EVENT_FAMILIES.join(", ")
                )));
            }
        }
    }
    Ok(values)
}

async fn resolve_record_labels(
    db: &Db,
    groups: &[ChangeGroup],
) -> Result<HashMap<String, (String, String)>> {
    let ids: HashSet<_> = groups
        .iter()
        .map(|group| group.key.record_id.clone())
        .collect();
    let mut labels = HashMap::new();
    for id in ids {
        if let Some(row) =
            sqlx::query("SELECT name, type FROM records WHERE id = ? AND deleted_at IS NULL")
                .bind(&id)
                .fetch_optional(db.write_pool())
                .await?
        {
            labels.insert(id, (row.try_get("name")?, row.try_get("type")?));
        }
    }
    Ok(labels)
}

fn normalized_next_request(
    args: &WhatsChangedArgs,
    actor_scope: ActorScope,
    accounts: &Option<BTreeSet<String>>,
    event_families: &Option<BTreeSet<String>>,
    next_after_seq: i64,
    high_water_seq: i64,
    limit: i64,
) -> Value {
    let mut request = serde_json::Map::new();
    request.insert("after_local_seq".into(), json!(next_after_seq));
    request.insert("through_local_seq".into(), json!(high_water_seq));
    request.insert("limit".into(), json!(limit));
    if let Some(scope_record_id) = &args.scope_record_id {
        request.insert("scope_record_id".into(), json!(scope_record_id));
    }
    request.insert("actor_scope".into(), json!(actor_scope));
    if let Some(accounts) = accounts {
        request.insert("accounts".into(), json!(accounts));
    }
    if let Some(for_run) = &args.for_run {
        request.insert("for_run".into(), json!(for_run));
    }
    request.insert("include_child_runs".into(), json!(args.include_child_runs));
    if let Some(event_families) = event_families {
        request.insert("event_families".into(), json!(event_families));
    }
    // Only a non-default order is echoed. Omission already means oldest-first,
    // so an oldest-first traversal's continuation stays byte-identical to the
    // one callers have been round-tripping.
    if !matches!(args.order, HistoryOrder::OldestFirst) {
        request.insert("order".into(), json!(args.order));
    }
    Value::Object(request)
}

/// Traversal costs for one `whats_changed` call, alongside its response.
///
/// The wire response deliberately reports only caller-visible counts, so this
/// accompanies the value on the in-crate path: it is what the release
/// benchmark harness records, and what shows a sparse filter reaching fewer
/// per-record authorization decisions than the rows the window returned.
///
/// Every counter names exactly what it counts; none claims to measure
/// SQLite's internal work.
/// - `window_rows_seen` counts rows the SQL window returned to the loop. Rows
///   the actor predicate filters inside SQLite never reach the loop and are
///   not counted; SQLite index/page scans behind the window are not counted
///   either.
/// - `record_auth_checks` counts top-level per-record `can_record` decisions
///   only. It excludes the acknowledgement/artefact checks inside
///   `event_is_visible`, the person-policy evaluations inside
///   `ActorDisclosure`, and — on the legacy path — the embedded-record walk
///   inside the full `redact_event`.
/// - `identity_lookups` counts post-authorization event-time identity
///   reconstructions for the `impacts` family.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TraversalMetrics {
    pub window_rows_seen: u64,
    pub record_auth_checks: u64,
    pub identity_lookups: u64,
}

/// Actor-filter contract, shared by the three places that enforce it. Read
/// all three when changing any one; `actor_filter_sql_matches_rust_checks`
/// below pins their agreement mechanically.
///
/// 1. [`change_actor_filter`] resolves the (scope, accounts) conjunction to
///    one [`events::ChangeActorFilter`], whose SQL predicate narrows the
///    `content_events` window.
/// 2. [`actor_scope_matches`] and [`accounts_match`] below apply the same
///    conjunction as pure comparisons, pre-authorization on the raw row and
///    again post-redaction on the redacted row (the loop calls the same
///    functions both times; there is only one definition of each).
/// 3. SQL is a superset of post-redaction matching, never narrower:
///    redaction only nulls an actor, and the caller's own token is always
///    disclosable to itself
///    ([`authorization::actor_disclosable_with`](crate::authorization::actor_disclosable_with)
///    returns true when principal and actor coincide), so `Only` is exact
///    while `Others`/`AnyOf` keep rows redaction will hide for the
///    post-redaction re-check to drop.
///
/// Whether a raw or redacted actor token survives the caller's actor scope.
fn actor_scope_matches(scope: ActorScope, caller_actor: &str, actor: Option<&str>) -> bool {
    match scope {
        ActorScope::All => true,
        ActorScope::Self_ => actor == Some(caller_actor),
        ActorScope::Others => actor != Some(caller_actor),
    }
}

/// Whether a raw or redacted actor token survives the caller's account list.
/// A hidden (redacted to `None`) actor never matches: callers cannot select
/// attribution they are not allowed to see.
fn accounts_match(accounts: &Option<BTreeSet<String>>, actor: Option<&str>) -> bool {
    accounts
        .as_ref()
        .is_none_or(|selected| actor.is_some_and(|actor| selected.contains(actor)))
}

/// The SQL actor window for one traversal: the conjunction of the caller's
/// actor scope and account list, resolved to the [`events::ChangeActorFilter`]
/// the window query enforces on `content_events.actor`. See the contract
/// above: this must stay a superset of the post-redaction checks.
fn change_actor_filter(
    scope: ActorScope,
    caller_actor: &str,
    accounts: &Option<BTreeSet<String>>,
) -> events::ChangeActorFilter {
    match (scope, accounts) {
        (ActorScope::All, None) => events::ChangeActorFilter::All,
        (ActorScope::All, Some(selected)) => {
            events::ChangeActorFilter::AnyOf(selected.iter().cloned().collect())
        }
        (ActorScope::Self_, None) => events::ChangeActorFilter::Only(caller_actor.to_owned()),
        (ActorScope::Self_, Some(selected)) => {
            if selected.contains(caller_actor) {
                events::ChangeActorFilter::Only(caller_actor.to_owned())
            } else {
                events::ChangeActorFilter::None
            }
        }
        (ActorScope::Others, None) => events::ChangeActorFilter::Others {
            caller: caller_actor.to_owned(),
        },
        (ActorScope::Others, Some(selected)) => {
            let rest: Vec<String> = selected
                .iter()
                .filter(|actor| actor.as_str() != caller_actor)
                .cloned()
                .collect();
            if rest.is_empty() {
                events::ChangeActorFilter::None
            } else {
                events::ChangeActorFilter::AnyOf(rest)
            }
        }
    }
}

/// The `whats_changed`-only form of [`redact_event`]: the actor-disclosure
/// gate, claim-holder handling, and canvas summarisation, without the
/// embedded-record authorization walk.
///
/// That walk is dead work on this path. `whats_changed` emits structural
/// summaries; the only payload-derived string is the generic facet `key` read
/// by [`changed_fields_for_payload`]. It never emits identity or
/// record-reference values. Full embedded-record redaction only nulls those
/// values and does not alter a generic `key`, so it cannot change the summaries
/// emitted here. The disclosure boundary that matters here (whose
/// actor/run/intent attribution travels with an event) is preserved verbatim
/// below; a corrupt payload is still normalized to `None` exactly as the full
/// redaction does, so downstream summaries observe the same input.
///
/// DRIFT WARNING: if [`changed_fields_for_payload`] or [`event_families`]
/// starts exposing payload values, re-audit this specialized redaction against
/// [`redact_event`] before relying on the embedded-record walk being dead work.
async fn redact_change_event(
    db: &Db,
    caller: &Caller,
    disclosure: &mut ActorDisclosure,
    event: &mut EventRow,
) -> Result<()> {
    crate::canvas::summarise_event_row(event);
    if super::is_legacy_local(caller) {
        return Ok(());
    }
    // Same gate as `redact_event`: attribution to a hidden actor is
    // attribution nobody can act on, so the run and intent travel with the
    // name under that same gate.
    let disclose_actor = match event.actor.as_deref() {
        Some(actor) => disclosure.visible(db, caller, actor).await?,
        None => false,
    };
    if !disclose_actor {
        event.actor = None;
        event.run_key = None;
        event.parent_key = None;
        event.intent = None;
    }
    let Some(raw) = event.payload.as_deref() else {
        return Ok(());
    };
    let Ok(payload) = serde_json::from_str::<Value>(raw) else {
        event.payload = None;
        return Ok(());
    };
    let claim_payload =
        payload.get("claimed_by_account").is_some() || payload.get("claimed_run_key").is_some();
    let claim_holder_visible = event.actor.as_deref() == Some(caller.credential())
        && event.run_key.as_deref() == caller.run_key();
    if claim_payload && !claim_holder_visible {
        event.run_key = None;
        event.parent_key = None;
        event.intent = None;
    }
    // The payload itself is intentionally left otherwise untouched: identity
    // and record-reference values never reach the response. A generic facet
    // `key` may reach `changed_fields`, but full redaction leaves that key
    // unchanged, so the summaries below are equivalent either way.
    Ok(())
}

async fn whats_changed(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    Ok(whats_changed_inner(db, caller, arguments).await?.0)
}

async fn whats_changed_inner(
    db: Db,
    caller: Caller,
    arguments: Value,
) -> Result<(Value, TraversalMetrics)> {
    let args: WhatsChangedArgs = parse_args("whats_changed", arguments)?;
    if args.include_child_runs && args.for_run.is_none() {
        return Err(Error::engine(
            "whats_changed include_child_runs requires for_run",
        ));
    }
    if let Some(run_key) = &args.for_run {
        match crate::runkey::validate_full(Some(run_key)) {
            crate::runkey::KeyOutcome::Valid(_) => {}
            crate::runkey::KeyOutcome::Malformed { complaint, .. } => {
                return Err(Error::engine(format!(
                    "invalid for_run '{run_key}': {complaint}"
                )))
            }
            _ => unreachable!("for_run is present and validate_full never mints keys"),
        }
    }

    let order = args.order.event_order();
    // The traversal cursor means "strictly after in traversal order", so an
    // omitted `after_seq` opens above the log when reading newest-first.
    let mut after_seq = args.after_seq.unwrap_or_else(|| order.initial_cursor());
    let limit = args.limit.unwrap_or(events::DEFAULT_CHANGE_WINDOW_LIMIT);
    if !(1..=events::MAX_CHANGE_WINDOW_LIMIT).contains(&limit) {
        return Err(Error::engine(format!(
            "whats_changed limit must be between 1 and {}",
            events::MAX_CHANGE_WINDOW_LIMIT
        )));
    }
    let actor_scope = args.actor_scope.unwrap_or_default();
    let accounts = normalize_accounts(args.accounts.clone())?;
    let selected_families = normalize_event_families(args.event_families.clone())?;
    if let Some(scope_record_id) = args.scope_record_id.as_deref() {
        require_public_history_record(&db, &caller, "whats_changed", scope_record_id).await?;
    }

    // `limit` is caller-visible page occupancy, not raw log occupancy. Walk the
    // pinned global sequence window in bounded chunks until this caller has a
    // full visible page plus one visible look-ahead event, or the pinned window
    // is exhausted. Hidden and filter-rejected rows may advance the public
    // synchronization cursor, but cannot shrink a page or manufacture has_more.
    let mut raw_cursor = after_seq;
    let mut high_water_seq = args.through_seq;
    let mut scope_ids = None;
    let mut selected_runs = None;
    let mut membership_initialized = false;
    // Assigned exactly once, on whichever loop exit fires: the look-ahead
    // parks it via `raw_seq_before_lookahead`, exhaustion takes the window's
    // far-end cursor. No incremental writes — every intermediate value would
    // be overwritten before any read.
    let scanned_through_seq: i64;
    let mut has_more = false;
    let mut matched = Vec::with_capacity(limit as usize);
    let mut actor_disclosure = ActorDisclosure::default();
    let mut metrics = TraversalMetrics::default();
    // The SQL window already enforces the actor conjunction below; it is
    // constructed once because it never moves under the pinned traversal.
    // `traversal_start` pins the cursor contract instead: the public cursor
    // still advances across actor-filtered gaps exactly as the unfiltered
    // window did, via `raw_seq_before_lookahead` at the look-ahead below.
    let actor_filter = change_actor_filter(actor_scope, caller.actor(), &accounts);
    let mut traversal_start = after_seq;
    'raw_pages: loop {
        // Membership is resolved on the first page only. Asking again on a
        // later chunk would re-read a subtree or run set that may have moved
        // since the pin, which is exactly what the pinned window exists to
        // prevent.
        let membership = if membership_initialized {
            events::ChangeMembership::default()
        } else {
            events::ChangeMembership {
                scope_record_id: args.scope_record_id.as_deref(),
                for_run: args.for_run.as_deref(),
                include_child_runs: args.include_child_runs,
            }
        };
        let snapshot = events::change_window_with_membership_filtered(
            db.write_pool(),
            raw_cursor,
            high_water_seq,
            events::MAX_CHANGE_WINDOW_LIMIT,
            membership,
            order,
            &actor_filter,
        )
        .await?;
        let raw_page = snapshot.page;
        if !membership_initialized {
            scope_ids = snapshot.scope_ids;
            selected_runs = snapshot.run_keys;
            high_water_seq = Some(raw_page.high_water_seq);
            // Newest-first opens above the pin; the window clamps that cursor,
            // and the caller is told the clamped position it actually got.
            after_seq = raw_page.after_seq;
            traversal_start = after_seq;
            membership_initialized = true;
        }
        let raw_has_more = raw_page.has_more;
        let raw_scanned_through_seq = raw_page.scanned_through_seq;
        for event in raw_page.events {
            metrics.window_rows_seen += 1;
            // Safe caller filters run before authorization: each decides on
            // the raw row alone and discloses nothing, so a rejected event
            // never costs an authorization decision, a visibility check, or
            // an identity reconstruction. The SQL window above already
            // enforces the actor conjunction; this re-check is the same pure
            // comparison, kept so the loop does not depend on the query for
            // its semantics.
            if !actor_scope_matches(actor_scope, caller.actor(), event.actor.as_deref()) {
                continue;
            }
            if !accounts_match(&accounts, event.actor.as_deref()) {
                continue;
            }
            if selected_runs
                .as_ref()
                .is_some_and(|runs| event.run_key.as_ref().is_none_or(|run| !runs.contains(run)))
            {
                continue;
            }
            // Family membership without `impacts` needs only the row's type
            // and payload keys, so it filters here too. `impacts` needs the
            // event-time identity reconstruction — history reads with
            // JSON/SQL — which stays behind authorization: when the caller
            // selected `impacts`, a row the cheap families reject must still
            // pass through auth to have its identity decided post-auth.
            if let Some(selected) = selected_families.as_ref() {
                if !selected.contains("impacts")
                    && selected.is_disjoint(&event_families_without_impact(&event)?)
                {
                    continue;
                }
            }
            // Authorization still precedes every disclosure: nothing below
            // this line observes event content, grouping, or labels.
            metrics.record_auth_checks += 1;
            if !can_record(&db, &caller, &event.record_id, Capability::View).await? {
                continue;
            }
            if !event_is_visible(&db, &caller, &event).await? {
                continue;
            }
            if scope_ids
                .as_ref()
                .is_some_and(|ids| !ids.contains(&event.record_id))
            {
                continue;
            }
            let mut event = event;
            // The change-window redaction is the full disclosure gate minus
            // the embedded-record walk (see its contract): attribution the
            // caller may not see is nulled here, before grouping.
            redact_change_event(&db, &caller, &mut actor_disclosure, &mut event).await?;
            // Redaction can only null the actor and run key, never invent
            // them, so these re-checks narrow the pre-authorization survivors
            // to exactly the post-redaction semantics callers already rely
            // on (a hidden actor never matches an account list, and takes
            // its run key with it). They run after this row's top-level
            // per-record authorization above, so they add comparisons but no
            // further authorization decisions.
            if !actor_scope_matches(actor_scope, caller.actor(), event.actor.as_deref()) {
                continue;
            }
            if !accounts_match(&accounts, event.actor.as_deref()) {
                continue;
            }
            if selected_runs
                .as_ref()
                .is_some_and(|runs| event.run_key.as_ref().is_none_or(|run| !runs.contains(run)))
            {
                continue;
            }
            // Identity reconstruction runs here, after authorization, exactly
            // where it ran before the reorder (it used to precede redaction;
            // redaction touches only the in-memory row, never the history it
            // reads, so the answer is unchanged). Rows the pre-auth gate
            // rejected never reach this query.
            let identity = event_time_identity(&db, &event).await?;
            metrics.identity_lookups += 1;
            let families = event_families(&event, is_impact_identity(&identity))?;
            if selected_families
                .as_ref()
                .is_some_and(|selected| selected.is_disjoint(&families))
            {
                continue;
            }
            if matched.len() == limit as usize {
                // This event is the caller-visible look-ahead. Do not consume
                // it: the next request must return it as the first candidate.
                // The cursor parks on the nearest committed sequence before
                // it — across any actor-filtered gap, exactly where the
                // unfiltered window would have scanned through — so the
                // continued request resumes without gaps or duplicates.
                scanned_through_seq = events::raw_seq_before_lookahead(
                    db.write_pool(),
                    order,
                    traversal_start,
                    event.local_seq,
                    high_water_seq.unwrap_or(after_seq),
                )
                .await?;
                has_more = true;
                break 'raw_pages;
            }
            matched.push((event, families));
        }
        if !raw_has_more {
            // A filtered page that exhausts its matches ends the traversal:
            // no later row can match the same stable predicate, and the
            // window already parked the cursor at the far end exactly as an
            // exhausted unfiltered window did.
            scanned_through_seq = raw_scanned_through_seq;
            break;
        }
        raw_cursor = raw_scanned_through_seq;
    }

    let matched_event_count = matched.len() as i64;
    let matched_events = matched
        .iter()
        .map(|(event, _)| event.clone())
        .collect::<Vec<_>>();
    let actor_names = resolve_actor_names(&db, &matched_events).await;
    let mut groups: Vec<ChangeGroup> = Vec::new();
    let mut group_indexes: HashMap<ChangeGroupKey, usize> = HashMap::new();
    for (event, families) in matched {
        let key = ChangeGroupKey {
            record_id: event.record_id.clone(),
            actor: event.actor.clone(),
            run_key: event.run_key.clone(),
        };
        if let Some(index) = group_indexes.get(&key).copied() {
            let group = &mut groups[index];
            // Sequence, not arrival, decides the extremes: a descending
            // traversal reaches a group's oldest event last.
            if event.local_seq < group.first_seq {
                group.first_seq = event.local_seq;
                group.first_event_at = event.created_at.clone();
            }
            if event.local_seq > group.last_seq {
                group.last_seq = event.local_seq;
                group.last_event_at = event.created_at.clone();
            }
            group.event_count += 1;
            group.event_types.insert(event.event_type.clone());
            group.event_families.extend(families);
            group.changed_fields.extend(changed_fields(&event)?);
        } else {
            let index = groups.len();
            group_indexes.insert(key.clone(), index);
            groups.push(ChangeGroup {
                key,
                first_seq: event.local_seq,
                last_seq: event.local_seq,
                first_event_at: event.created_at.clone(),
                last_event_at: event.created_at.clone(),
                event_count: 1,
                event_types: BTreeSet::from([event.event_type.clone()]),
                event_families: families,
                changed_fields: changed_fields(&event)?,
            });
        }
    }
    // Newest-first sorts on the group's most recent event, not its first: a
    // record touched long ago and again just now belongs at the top of a
    // recency read, and its `first_seq` would bury it.
    groups.sort_by(|left, right| {
        match order {
            events::EventOrder::OldestFirst => left.first_seq.cmp(&right.first_seq),
            events::EventOrder::NewestFirst => right.last_seq.cmp(&left.last_seq),
        }
        .then_with(|| left.key.cmp(&right.key))
    });
    let record_labels = resolve_record_labels(&db, &groups).await?;
    let changes = groups
        .into_iter()
        .map(|group| {
            let label = record_labels.get(&group.key.record_id);
            let actor_name = group.key.actor.as_ref().map(|actor| {
                actor_names
                    .get(actor)
                    .cloned()
                    .unwrap_or_else(|| actor.clone())
            });
            json!({
                "record_id": group.key.record_id,
                "record_name": label.map(|(name, _)| name),
                "record_type": label.map(|(_, record_type)| record_type),
                "actor": group.key.actor,
                "actor_name": actor_name,
                "run_key": group.key.run_key,
                "first_local_seq": group.first_seq,
                "last_local_seq": group.last_seq,
                "first_event_at": group.first_event_at,
                "last_event_at": group.last_event_at,
                "event_count": group.event_count,
                "event_types": group.event_types,
                "event_families": group.event_families,
                "changed_fields": group.changed_fields,
            })
        })
        .collect::<Vec<_>>();
    let high_water_seq = high_water_seq.unwrap_or(after_seq);
    let next_after_seq = has_more.then_some(scanned_through_seq);
    let next_request = next_after_seq.map(|next| {
        normalized_next_request(
            &args,
            actor_scope,
            &accounts,
            &selected_families,
            next,
            high_water_seq,
            limit,
        )
    });

    Ok((
        json!({
            "local_database_id": crate::identity::database_id(&db).await?,
            "after_local_seq": after_seq,
            "scanned_through_local_seq": scanned_through_seq,
            "high_water_local_seq": high_water_seq,
            "next_after_local_seq": next_after_seq,
            "has_more": has_more,
            // Compatibility field: this is deliberately caller-visible after
            // authorization and every filter, never the number of raw rows read.
            "scanned_event_count": matched_event_count,
            "matched_event_count": matched_event_count,
            "changes": changes,
            "next_request": next_request,
        }),
        metrics,
    ))
}

async fn require_public_history_record(
    db: &Db,
    caller: &Caller,
    tool: &str,
    record_id: &str,
) -> Result<()> {
    require_record(db, caller, tool, record_id, Capability::View).await?;
    let acknowledgement = crate::query::acknowledgement_predicate("r");
    let hidden_acknowledgement: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM records r WHERE r.id=? AND {acknowledgement})"
    ))
    .bind(record_id)
    .fetch_one(db.write_pool())
    .await?;
    if hidden_acknowledgement {
        return Err(Error::engine(format!(
            "{tool}: record {record_id} does not exist"
        )));
    }
    Ok(())
}

async fn get_history(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: GetHistoryArgs = parse_args("get_history", arguments)?;
    if args.include_child_runs && args.for_run.is_none() {
        return Err(Error::engine(
            "get_history include_child_runs requires for_run",
        ));
    }
    let limit = args.limit.unwrap_or(DEFAULT_PAGE);
    if limit <= 0 || limit > 1000 {
        return Err(Error::engine(
            "get_history limit must be between 1 and 1000",
        ));
    }
    if let Some(record_id) = args.record_id.as_deref() {
        require_public_history_record(&db, &caller, "get_history", record_id).await?;
    }
    if args.for_run.is_none() {
        if let Some(record_id) = args.record_id.as_deref() {
            return get_record_history_in(
                &db,
                &caller,
                record_id,
                args.after_seq,
                limit,
                args.order,
                args.detail,
            )
            .await;
        }
    }
    let mut cursor = args.after_seq;
    let mut selected = Vec::new();
    let mut exhausted = false;
    let mut actor_disclosure = ActorDisclosure::default();
    while selected.len() < limit as usize && !exhausted {
        let page = match &args.for_run {
            Some(run_key) => {
                match crate::runkey::validate_full(Some(run_key)) {
                    crate::runkey::KeyOutcome::Valid(_) => {}
                    crate::runkey::KeyOutcome::Malformed { complaint, .. } => {
                        return Err(Error::engine(format!(
                            "invalid for_run '{run_key}': {complaint}"
                        )))
                    }
                    _ => unreachable!("for_run is present and validate_full never mints keys"),
                }
                events::events_for_run_ordered(
                    &db,
                    run_key,
                    args.include_child_runs,
                    args.record_id.as_deref(),
                    cursor,
                    1000,
                    args.order.event_order(),
                )
                .await?
            }
            None => match &args.record_id {
                Some(record_id) => {
                    events::events_for_record_ordered(
                        &db,
                        record_id,
                        cursor,
                        1000,
                        args.order.event_order(),
                    )
                    .await?
                }
                None => {
                    events::all_events_ordered(&db, cursor, 1000, args.order.event_order()).await?
                }
            },
        };
        let raw_exhausted = page.next_after_seq.is_none();
        let raw_len = page.events.len();
        let mut processed = 0usize;
        for mut event in page.events {
            cursor = Some(event.local_seq);
            processed += 1;
            if args.record_id.is_none()
                && !can_record(&db, &caller, &event.record_id, Capability::View).await?
            {
                continue;
            }
            if !event_is_visible(&db, &caller, &event).await? {
                continue;
            }
            redact_event(&db, &caller, &mut actor_disclosure, &mut event).await?;
            selected.push(event);
            if selected.len() == limit as usize {
                break;
            }
        }
        exhausted = raw_exhausted && processed == raw_len;
    }
    let actor_names = resolve_actor_names(&db, &selected).await;
    Ok(json!({
        "local_database_id": crate::identity::database_id(&db).await?,
        "events": selected.iter().map(|event| {
            shape_history_event(event_to_value(event, &actor_names), args.detail)
        }).collect::<Vec<_>>(),
        "next_after_local_seq": if exhausted { None } else { cursor },
        "order": args.order,
        "representation": history_representation(args.detail),
    }))
}

async fn get_record_history_in(
    db: &Db,
    caller: &Caller,
    record_id: &str,
    after_seq: Option<i64>,
    limit: i64,
    order: HistoryOrder,
    detail: HistoryDetail,
) -> Result<Value> {
    let local_database_id = crate::identity::database_id(db).await?;
    let mut snapshot = db.write_pool().begin().await?;
    let result = async {
        super::require_record_in(
            &mut snapshot,
            caller,
            "get_history",
            record_id,
            Capability::View,
        )
        .await?;
        let mut cursor = after_seq;
        let mut selected = Vec::new();
        let mut exhausted = false;
        let mut actor_disclosure = ActorDisclosure::default();
        while selected.len() < limit as usize && !exhausted {
            let page = events::events_for_record_ordered_in(
                &mut snapshot,
                record_id,
                cursor,
                1000,
                order.event_order(),
            )
            .await?;
            let raw_exhausted = page.next_after_seq.is_none();
            let raw_len = page.events.len();
            let mut processed = 0usize;
            for mut event in page.events {
                cursor = Some(event.local_seq);
                processed += 1;
                if !event_is_visible_in(&mut snapshot, caller, &event).await? {
                    continue;
                }
                redact_event_in(&mut snapshot, caller, &mut actor_disclosure, &mut event).await?;
                selected.push(event);
                if selected.len() == limit as usize {
                    break;
                }
            }
            exhausted = raw_exhausted && processed == raw_len;
        }
        let actor_names = resolve_actor_names_in(&mut snapshot, &selected).await;
        Ok::<_, Error>(json!({
            "local_database_id": local_database_id,
            "events": selected.iter().map(|event| {
                shape_history_event(event_to_value(event, &actor_names), detail)
            }).collect::<Vec<_>>(),
            "next_after_local_seq": if exhausted { None } else { cursor },
            "order": order,
            "representation": history_representation(detail),
        }))
    }
    .await;
    snapshot.rollback().await?;
    result
}

/// Aggregate-only projection of one run's disposable attention exhaust.
///
/// The query names every permitted read-log column. In particular it never
/// selects `read_log_calls.arguments`, which contains verbatim and failed
/// query text. Any read-log failure produces a sanitized unavailable envelope:
/// deleting the user's attention history cannot break this or any core
/// operation, and callers can distinguish that case from an available run with
/// no aggregate activity.
fn run_activity_result(
    for_run: &str,
    include_child_runs: bool,
    read_activity: Vec<Value>,
    unavailable_reason: Option<&str>,
    visibility_filtered: Option<bool>,
) -> Value {
    json!({
        "for_run": for_run,
        "include_child_runs": include_child_runs,
        "availability": {
            "status": if unavailable_reason.is_some() { "unavailable" } else { "available" },
            "reason": unavailable_reason,
            "visibility_filtered": visibility_filtered,
        },
        "read_activity": read_activity,
    })
}

async fn get_run_activity(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: GetRunActivityArgs = parse_args("get_run_activity", arguments)?;
    let Some(run_key) = args.for_run.as_deref() else {
        if args.include_child_runs.is_some() {
            return Err(Error::engine(
                "get_run_activity: include_child_runs requires for_run",
            ));
        }
        return discover_own_runs(&db, &caller, args.cursor, args.limit).await;
    };
    if args.cursor.is_some() || args.limit.is_some() {
        return Err(Error::engine(
            "get_run_activity: cursor and limit are discovery-only; omit for_run to discover runs",
        ));
    }
    let include_child_runs = args.include_child_runs.unwrap_or(false);
    match crate::runkey::validate_full(Some(run_key)) {
        crate::runkey::KeyOutcome::Valid(_) => {}
        crate::runkey::KeyOutcome::Malformed { complaint, .. } => {
            return Err(Error::engine(format!(
                "invalid for_run '{run_key}': {complaint}"
            )))
        }
        _ => unreachable!("for_run is present and validate_full never mints keys"),
    }

    let legacy_local = super::is_legacy_local(&caller);
    if !legacy_local {
        let owns_root = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM read_log_calls
              WHERE run_key = ? AND actor = ?)",
        )
        .bind(run_key)
        .bind(caller.credential())
        .fetch_one(db.write_pool())
        .await;
        match owns_root {
            Ok(false) => return Err(Error::engine("get_run_activity: run does not exist")),
            Ok(true) => {}
            Err(_) => {
                return Ok(run_activity_result(
                    run_key,
                    include_child_runs,
                    Vec::new(),
                    Some("read_log_unavailable"),
                    None,
                ))
            }
        }
    }

    let rows = sqlx::query(
        "WITH RECURSIVE included_runs(run_key) AS (
             SELECT ?
             UNION
             SELECT call.run_key
               FROM read_log_calls call
               JOIN included_runs parent ON call.parent_key = parent.run_key
              WHERE ? AND call.run_key IS NOT NULL
             UNION
             SELECT event.run_key
               FROM content_events event
               JOIN included_runs parent ON event.parent_key = parent.run_key
              WHERE ? AND event.run_key IS NOT NULL
         ),
         selected_calls AS (
             SELECT call.seq, call.run_key, call.parent_key, call.tool
               FROM read_log_calls call
               JOIN included_runs included ON included.run_key = call.run_key
              WHERE ? OR call.actor = ?
         )
         SELECT call.seq, call.run_key, call.parent_key, call.tool,
                touch.record_id AS touch_record_id,
                touch.interaction AS touch_interaction
           FROM selected_calls call
           LEFT JOIN read_log_touches touch ON touch.call_seq = call.seq
          ORDER BY call.seq, touch.record_id, touch.interaction",
    )
    .bind(run_key)
    .bind(include_child_runs)
    .bind(include_child_runs)
    .bind(legacy_local)
    .bind(caller.credential())
    .fetch_all(db.write_pool())
    .await;

    let rows = match rows {
        Ok(rows) => rows,
        Err(_) => {
            return Ok(run_activity_result(
                run_key,
                include_child_runs,
                Vec::new(),
                Some("read_log_unavailable"),
                None,
            ))
        }
    };
    let read_activity = async {
        #[derive(Default)]
        struct Activity {
            parent_key: Option<String>,
            searches: i64,
            surfaced: i64,
            opened: i64,
            mutated: i64,
        }

        let mut order = Vec::new();
        let mut activity: HashMap<String, Activity> = HashMap::new();
        let mut counted_calls = HashSet::new();
        let mut visibility_filtered = false;
        for row in rows {
            let seq: i64 = row.try_get("seq")?;
            let row_run: String = row.try_get("run_key")?;
            let entry = activity.entry(row_run.clone()).or_insert_with(|| {
                order.push(row_run.clone());
                Activity::default()
            });
            if entry.parent_key.is_none() && row_run != run_key {
                entry.parent_key = row.try_get("parent_key")?;
            }
            if counted_calls.insert(seq) && row.try_get::<String, _>("tool")? == "search" {
                entry.searches += 1;
            }
            let Some(record_id) = row.try_get::<Option<String>, _>("touch_record_id")? else {
                continue;
            };
            if !can_record(&db, &caller, &record_id, Capability::View).await? {
                visibility_filtered = true;
                continue;
            }
            match row
                .try_get::<Option<String>, _>("touch_interaction")?
                .as_deref()
            {
                Some("surfaced") => entry.surfaced += 1,
                Some("opened") => entry.opened += 1,
                Some("mutated") => entry.mutated += 1,
                _ => {}
            }
        }
        Ok::<_, Error>((
            order
                .into_iter()
                .filter_map(|run| {
                    let activity = activity.remove(&run)?;
                    (activity.searches > 0
                        || activity.surfaced > 0
                        || activity.opened > 0
                        || activity.mutated > 0)
                        .then(|| {
                            json!({
                                "run_key": run,
                                "parent_key": activity.parent_key,
                                "searches": activity.searches,
                                "surfaced": activity.surfaced,
                                "opened": activity.opened,
                                "mutated": activity.mutated,
                            })
                        })
                })
                .collect::<Vec<_>>(),
            visibility_filtered,
        ))
    }
    .await;
    let (read_activity, visibility_filtered) = match read_activity {
        Ok(read_activity) => read_activity,
        Err(_) => {
            return Ok(run_activity_result(
                run_key,
                include_child_runs,
                Vec::new(),
                Some("activity_projection_unavailable"),
                None,
            ))
        }
    };
    Ok(run_activity_result(
        run_key,
        include_child_runs,
        read_activity,
        None,
        Some(visibility_filtered),
    ))
}

async fn discover_own_runs(
    db: &Db,
    caller: &Caller,
    cursor: Option<RunDiscoveryCursor>,
    limit: Option<i64>,
) -> Result<Value> {
    let limit = limit.unwrap_or(RUN_DISCOVERY_DEFAULT_LIMIT);
    if !(1..=RUN_DISCOVERY_MAX_LIMIT).contains(&limit) {
        return Err(Error::engine(format!(
            "get_run_activity: discovery limit must be between 1 and {RUN_DISCOVERY_MAX_LIMIT}"
        )));
    }
    if let Some(cursor) = cursor.as_ref() {
        chrono::DateTime::parse_from_rfc3339(&cursor.observed_at)
            .map_err(|_| Error::engine("get_run_activity: cursor observed_at must be RFC 3339"))?;
        chrono::DateTime::parse_from_rfc3339(&cursor.sort_at)
            .map_err(|_| Error::engine("get_run_activity: cursor sort_at must be RFC 3339"))?;
        if !matches!(cursor.open_rank, 0 | 1) || cursor.activity_id.trim().is_empty() {
            return Err(Error::engine("get_run_activity: invalid discovery cursor"));
        }
    }
    let observed_at = cursor
        .as_ref()
        .map(|cursor| cursor.observed_at.clone())
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    let observed = chrono::DateTime::parse_from_rfc3339(&observed_at)
        .expect("new and validated cursor observation times parse")
        .with_timezone(&chrono::Utc);
    let cutoff = (observed - chrono::Duration::hours(RUN_DISCOVERY_RECENT_HOURS))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let cursor_rank = cursor.as_ref().map(|cursor| cursor.open_rank);
    let cursor_sort = cursor.as_ref().map(|cursor| cursor.sort_at.as_str());
    let cursor_id = cursor.as_ref().map(|cursor| cursor.activity_id.as_str());
    let rows = sqlx::query(
        "WITH candidates AS (
             SELECT activity_id,run_key,started_at,
                    CASE WHEN ended_at IS NOT NULL AND ended_at<=? THEN ended_at END AS observed_ended_at,
                    CASE WHEN ended_at IS NULL OR ended_at>? THEN 0 ELSE 1 END AS open_rank,
                    CASE WHEN ended_at IS NULL OR ended_at>? THEN started_at ELSE ended_at END AS sort_at
               FROM agent_runs
              WHERE account_id=? AND started_at<=?
                AND (ended_at IS NULL OR ended_at>?)
         )
         SELECT activity_id,run_key,started_at,observed_ended_at,open_rank,sort_at
           FROM candidates
          WHERE ? IS NULL
             OR open_rank>?
             OR (open_rank=? AND (sort_at<? OR (sort_at=? AND activity_id>?)))
          ORDER BY open_rank,sort_at DESC,activity_id
          LIMIT ?",
    )
    .bind(&observed_at)
    .bind(&observed_at)
    .bind(&observed_at)
    .bind(caller.credential())
    .bind(&observed_at)
    .bind(&cutoff)
    .bind(cursor_rank)
    .bind(cursor_rank)
    .bind(cursor_rank)
    .bind(cursor_sort)
    .bind(cursor_sort)
    .bind(cursor_id)
    .bind(limit + 1)
    .fetch_all(db.write_pool())
    .await?;
    let has_more = rows.len() as i64 > limit;
    let page = rows.iter().take(limit as usize);
    let mut runs = Vec::with_capacity(rows.len().min(limit as usize));
    for row in page {
        let run_key: String = row.try_get("run_key")?;
        let started_at: String = row.try_get("started_at")?;
        let ended_at: Option<String> = row.try_get("observed_ended_at")?;
        let intent = latest_discovery_intent(db, caller, &run_key, &observed_at).await;
        let activity = discovery_activity_freshness(
            db,
            caller,
            &run_key,
            &started_at,
            ended_at.as_deref(),
            &observed_at,
        )
        .await?;
        runs.push(json!({
            "activity_id": row.try_get::<String, _>("activity_id")?,
            "run_key": run_key,
            "intent": intent,
            "started_at": started_at,
            "ended_at": ended_at,
            "run_state": if ended_at.is_some() { "closed" } else { "open" },
            "activity_freshness": activity,
        }));
    }
    let next_cursor = if has_more {
        let row = &rows[limit as usize - 1];
        Some(RunDiscoveryCursor {
            observed_at: observed_at.clone(),
            open_rank: row.try_get("open_rank")?,
            sort_at: row.try_get("sort_at")?,
            activity_id: row.try_get("activity_id")?,
        })
    } else {
        None
    };
    Ok(json!({
        "mode": "discovery",
        "scope": "own_account",
        "availability": {
            "status": "available",
            "enumeration": "durable_agent_runs",
            "details": "best_effort",
            "visibility": "own_account_only",
        },
        "observed_at": observed_at,
        "recent_window_hours": RUN_DISCOVERY_RECENT_HOURS,
        "runs": runs,
        "returned": runs.len(),
        "limit": limit,
        "has_more": has_more,
        "next_cursor": next_cursor,
    }))
}

async fn latest_discovery_intent(
    db: &Db,
    caller: &Caller,
    run_key: &str,
    observed_at: &str,
) -> Value {
    let row = sqlx::query(
        "SELECT intent,started_at FROM read_log_calls
          WHERE run_key=? AND actor=? AND tool='set_intent' AND outcome='ok'
            AND intent IS NOT NULL AND ended_at<=?
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(run_key)
    .bind(caller.credential())
    .bind(observed_at)
    .fetch_optional(db.write_pool())
    .await;
    match row {
        Ok(Some(row)) => match (
            row.try_get::<String, _>("intent"),
            row.try_get::<String, _>("started_at"),
        ) {
            (Ok(intent), Ok(declared_at)) => json!({
                "status": "available",
                "value": intent,
                "declared_at": declared_at,
            }),
            _ => json!({ "status": "unavailable", "reason": "intent_projection_unavailable" }),
        },
        Ok(None) => json!({
            "status": "not_retained",
            "reason": "no_retained_declaration_at_boundary"
        }),
        Err(_) => json!({ "status": "unavailable", "reason": "read_log_unavailable" }),
    }
}

async fn discovery_activity_freshness(
    db: &Db,
    caller: &Caller,
    run_key: &str,
    started_at: &str,
    ended_at: Option<&str>,
    observed_at: &str,
) -> Result<Value> {
    let durable: Option<String> = sqlx::query_scalar(
        "SELECT MAX(created_at) FROM content_events
          WHERE run_key=? AND actor=? AND created_at<=?",
    )
    .bind(run_key)
    .bind(caller.credential())
    .bind(observed_at)
    .fetch_one(db.write_pool())
    .await?;
    let transient = sqlx::query_scalar::<_, Option<String>>(
        "SELECT MAX(ended_at) FROM read_log_calls
          WHERE run_key=? AND actor=? AND outcome='ok' AND ended_at<=?",
    )
    .bind(run_key)
    .bind(caller.credential())
    .bind(observed_at)
    .fetch_one(db.write_pool())
    .await;
    let (transient, status, reason) = match transient {
        Ok(value) => (value, "available", Value::Null),
        Err(_) => (
            None,
            "partial",
            Value::String("read_log_unavailable".into()),
        ),
    };
    let last_observed_at = [Some(started_at.to_string()), durable, transient]
        .into_iter()
        .flatten()
        .max()
        .expect("run start is always present");
    let active_until = chrono::DateTime::parse_from_rfc3339(&last_observed_at)
        .map_err(|_| Error::engine("get_run_activity: stored activity time is malformed"))?
        .with_timezone(&chrono::Utc)
        + chrono::Duration::minutes(5);
    let observation = chrono::DateTime::parse_from_rfc3339(observed_at)
        .expect("validated observation time parses")
        .with_timezone(&chrono::Utc);
    Ok(json!({
        "status": status,
        "reason": reason,
        "last_observed_at": last_observed_at,
        "active_until": active_until.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "appears_active": ended_at.is_none() && observation < active_until,
    }))
}

pub(crate) async fn record_version_at(
    db: &Db,
    caller: &Caller,
    record_id: &str,
    seq: i64,
) -> Result<Value> {
    if seq < 1 {
        return Err(Error::engine("get_record_version seq must be positive"));
    }
    let resolved = lens::resolve_as_of(
        db,
        AsOfSelector::ContentSeq(ContentSeqSelector { content_seq: seq }),
    )
    .await?;

    let scratch = open_database(":memory:").await?;
    let result: Result<Option<read::EnrichedRecord>> = async {
        apply_schema(&scratch).await?;
        lens::replay_projection(db, &scratch, resolved.resolved_content_seq).await?;
        let read_lens = ReadLens::historical(&scratch, db, &resolved);
        let record = read::get_record_with_lens_as(
            &read_lens,
            record_id,
            read::EnrichOptions::default(),
            super::principal(caller),
        )
        .await?;
        let Some(mut record) = record else {
            return Ok(None);
        };
        super::lifecycle::filter_enriched_record_with_auth(
            &scratch,
            db,
            caller,
            &mut record,
            read::EnrichOptions::default(),
        )
        .await?;
        Ok(Some(record))
    }
    .await;
    scratch.close().await;

    match result? {
        Some(record) => Ok(json!({ "as_of_seq": seq, "record": record })),
        None => Err(Error::engine(format!(
            "record {} has no state as of seq {}",
            record_id, seq
        ))),
    }
}

/// Register the history pair and the aggregate-only run-attention projection.
pub fn register_history_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::GetHistory,
        "Authorized database-local replay pages. Metadata is default; detail=full includes payloads.",
        json!({
            "type": "object",
            "properties": {
                "record_id": {
                    "type": "string",
                    "description": "One record's stream; omit for the whole log."
                },
                "for_run": {
                    "type": "string",
                    "description": "Exact run to query, as a complete handle-disambiguator-run_id key. This is distinct from the caller's universal run_key correlation argument; sentinels are invalid here."
                },
                "include_child_runs": {
                    "type": "boolean",
                    "default": false,
                    "description": "With for_run, include all recursively descended runs asserted through content-event parent_key values. Events remain globally seq-ordered and retain their own run_key and parent_key."
                },
                "after_local_seq": {
                    "type": "integer",
                    "description": "Cursor scoped to local_database_id; use the prior page's last local_seq."
                },
                "limit": {
                    "type": "integer",
                    "description": "Page size (default 100, capped by the engine)."
                },
                "order": {
                    "type": "string",
                    "enum": ["oldest_first", "newest_first"],
                    "default": "oldest_first",
                    "description": "Event order. Pass next_after_local_seq back as after_local_seq in either direction."
                },
                "detail": {
                    "type": "string",
                    "enum": ["metadata", "full"],
                    "default": "metadata",
                    "description": "metadata (default) omits payload; full includes it."
                }
            },
            "additionalProperties": false
        }),
        get_history,
    )?;
    registry.register(
        ToolKind::WhatsChanged,
        "Return a stable, authorization-filtered window over the authoritative content event log. The first page pins a public synchronization high-water sequence, visible events fill the requested page after every caller filter, and the server stores no progress state. Pass next_request back verbatim until it becomes null.",
        json!({
            "type": "object",
            "properties": {
                "after_local_seq": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 0,
                    "description": "Exclusive local cursor scoped to local_database_id; not portable or causal."
                },
                "through_local_seq": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Pinned inclusive local high-water; omit first, preserve thereafter."
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1000,
                    "default": 200,
                    "description": "Maximum caller-visible events returned after authorization and every supplied filter."
                },
                "scope_record_id": {
                    "type": "string",
                    "description": "Restrict matching events to this record's current live, visible, unarchived subtree."
                },
                "actor_scope": {
                    "type": "string",
                    "enum": ["all", "self", "others"],
                    "default": "all",
                    "description": "Account comparison against the authenticated caller. Others includes unattributed events."
                },
                "accounts": {
                    "type": "array",
                    "minItems": 1,
                    "items": { "type": "string" },
                    "description": "Exact opaque account actor tokens. Duplicates normalized; max 1000 distinct."
                },
                "for_run": {
                    "type": "string",
                    "description": "Exact run to select, as a complete handle-disambiguator-run_id key."
                },
                "include_child_runs": {
                    "type": "boolean",
                    "default": false,
                    "description": "With for_run, also include recursively descended runs asserted through content-event parent_key values."
                },
                "event_families": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "string",
                        "enum": ["created", "updated", "moved", "facets", "impacts", "links", "annotations", "deleted"]
                    },
                    "description": "Mechanical event families. impacts selects ordinary events whose event-time record identity is Outcome kind:impact. One event may contribute more than one family. Duplicates are normalized away."
                },
                "order": {
                    "type": "string",
                    "enum": ["oldest_first", "newest_first"],
                    "default": "oldest_first",
                    "description": "Traversal direction; pass the cursor back as after_local_seq."
                }
            },
            "additionalProperties": false
        }),
        whats_changed,
    )?;
    registry.register(
        ToolKind::GetRunActivity,
        "With for_run, aggregate read activity for that run and optional descendants; no intent or raw trace data. Without for_run, page the caller account's open or recent durable runs with keys, retained-intent status, and best-effort freshness. Other accounts are excluded. Missing evidence is not_retained; log failure is unavailable.",
        json!({
            "type": "object",
            "properties": {
                "for_run": {
                    "type": "string",
                    "description": "Exact full run key to query; distinct from caller correlation; sentinels are invalid."
                },
                "include_child_runs": {
                    "type": "boolean",
                    "default": false,
                    "description": "With for_run, include recursively descended runs."
                },
                "cursor": {
                    "type": "object",
                    "properties": {
                        "observed_at": { "type": "string", "format": "date-time" },
                        "open_rank": { "type": "integer", "enum": [0, 1] },
                        "sort_at": { "type": "string", "format": "date-time" },
                        "activity_id": { "type": "string", "minLength": 1 }
                    },
                    "required": ["observed_at", "open_rank", "sort_at", "activity_id"],
                    "additionalProperties": false,
                    "description": "Discovery continuation returned by the preceding page."
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 50,
                    "default": 20,
                    "description": "Discovery page size; valid only when for_run is omitted."
                }
            },
            "additionalProperties": false
        }),
        get_run_activity,
    )?;
    Ok(())
}

#[cfg(test)]
mod actor_filter_agreement_tests {
    use super::*;
    use events::ChangeActorFilter;

    /// Mirror of the SQL predicate [`ChangeActorFilter`] generates, under
    /// SQLite three-valued logic: `NULL = ?` and `NULL IN (...)` are never
    /// true, so a null actor only passes via the explicit `IS NULL` arm.
    fn sql_keeps(filter: &ChangeActorFilter, raw: Option<&str>) -> bool {
        match filter {
            ChangeActorFilter::All => true,
            ChangeActorFilter::Only(actor) => raw == Some(actor.as_str()),
            ChangeActorFilter::Others { caller } => {
                raw.is_none_or(|actor| actor != caller.as_str())
            }
            ChangeActorFilter::AnyOf(list) => {
                raw.is_some_and(|actor| list.iter().any(|kept| kept == actor))
            }
            ChangeActorFilter::None => false,
        }
    }

    /// The SQL window and the pre-authorization Rust checks agree as follows,
    /// for every scope/accounts conjunction and every shape of raw actor:
    /// satisfiable conjunctions keep exactly the same rows in SQL and in
    /// Rust; unsatisfiable ones resolve to `None`, which keeps nothing — and
    /// the Rust checks keep nothing either, so no final match is lost. The
    /// post-redaction leg of the contract (redaction only nulls; a nulled
    /// actor matches `others` but no account list) is pinned instead by the
    /// `hidden_actor_*` and `unsatisfiable_*` tool tests, which observe
    /// redacted rows end to end.
    #[test]
    fn actor_filter_sql_matches_rust_checks() {
        let caller = "account:self";
        let other = "account:other";
        let stranger = "account:z";
        let account_sets: Vec<Option<BTreeSet<String>>> = vec![
            None,
            Some(BTreeSet::from([caller.to_string()])),
            Some(BTreeSet::from([other.to_string()])),
            Some(BTreeSet::from([caller.to_string(), other.to_string()])),
            Some(BTreeSet::from([stranger.to_string()])),
        ];
        let raw_actors: Vec<Option<&str>> = vec![None, Some(caller), Some(other), Some(stranger)];
        for scope in [ActorScope::All, ActorScope::Self_, ActorScope::Others] {
            for accounts in &account_sets {
                let filter = change_actor_filter(scope, caller, accounts);
                for raw in &raw_actors {
                    let rust_keeps =
                        actor_scope_matches(scope, caller, *raw) && accounts_match(accounts, *raw);
                    if matches!(filter, ChangeActorFilter::None) {
                        assert!(
                            !rust_keeps,
                            "scope={scope:?} accounts={accounts:?} raw={raw:?}: \
                             unsatisfiable SQL must match unsatisfiable checks"
                        );
                    } else {
                        assert_eq!(
                            sql_keeps(&filter, *raw),
                            rust_keeps,
                            "scope={scope:?} accounts={accounts:?} raw={raw:?}"
                        );
                    }
                }
            }
        }
    }
}
