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
// The coordination surfaces this evaluator reads *by shape* — it inspects
// their verbatim arguments, not just the fact that they ran — come from the
// action-evidence carve-out, which is the single authority for what capture
// must keep raw. `START_WORK`, `MANAGE_LINKS` and `CREATE_RECORD` are used
// as match patterns below and must stay `const`: a `let` of the same name
// would be an irrefutable binding that matches every tool, and
// `is_explicit_coordination` would return true for all of them with no
// compile error.
use crate::mcp::action_evidence::{self, CREATE_RECORD, MANAGE_LINKS, START_WORK};
use crate::provenance::Channel;
use crate::query::{events, read};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{can_record, can_record_in, can_record_in_pool, parse_args, require_record};

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
    channel: String,
    executor_kind: Option<String>,
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
    channel_assurance: &'static str,
    executor_assurance: &'static str,
}

/// Server-observed provenance for one `whats_changed` event.
///
/// `(channel_kind, channel_assurance, executor_kind, executor_assurance)`.
/// Missing or invalidated attestations collapse to
/// `("unknown", "unknown_or_withheld", None, "unknown_or_withheld")`.
/// The executor class is never derived from the channel or the run key.
type ChangeProvenance = (String, &'static str, Option<String>, &'static str);

fn provenance_for_change(
    channel: Channel,
    attested: bool,
    executor_kind: Option<String>,
) -> ChangeProvenance {
    let kind = channel.as_str().to_string();
    let channel_assurance = if attested && channel.is_observed() {
        "server_observed"
    } else {
        "unknown_or_withheld"
    };
    let executor_assurance = if attested {
        "engine_attested"
    } else {
        "unknown_or_withheld"
    };
    let (kind, executor_kind) = if attested {
        (kind, executor_kind)
    } else {
        ("unknown".to_string(), None)
    };
    (kind, channel_assurance, executor_kind, executor_assurance)
}

/// Batch the existing valid-attestation join over `matched` event ids.
///
/// Runs after authorization and actor-disclosure gates; callers only learn
/// about events they may already see. Chunked to stay under SQLite's
/// bind-variable ceiling on large pages.
async fn change_provenance_map(
    db: &Db,
    event_ids: &[String],
) -> Result<HashMap<String, ChangeProvenance>> {
    use std::collections::{HashMap as Map, HashSet};
    // event_id -> (raw channel, executor_kind, attestation_id). First row
    // wins, and the query's ORDER BY puts the outputs arm first, so that
    // priority is deterministic even for a dual-linked event.
    let mut attested: Map<String, (Option<String>, Option<String>, String)> = Map::new();
    for chunk in event_ids.chunks(200) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
        // A dual-linked event (rows in both arms) is unreachable in
        // production but constructible in tests. The Rust fold below takes
        // the first row per event, so source priority is explicit here in
        // SQL — current outputs arm before the legacy events arm — rather
        // than relying on the arms' return order.
        let sql = format!(
            "SELECT o.output_event_id AS event_id, a.channel AS channel,
                    a.executor_kind AS executor_kind, a.id AS attestation_id,
                    0 AS src
               FROM provenance_action_outputs o
               JOIN provenance_action_attestations a
                 ON a.id = o.action_attestation_id
              WHERE o.output_domain = 'content' AND o.output_event_id IN ({placeholders})
              UNION ALL
             SELECT e.output_event_id AS event_id, a.channel AS channel,
                    a.executor_kind AS executor_kind, a.id AS attestation_id,
                    1 AS src
               FROM provenance_action_events e
               JOIN provenance_action_attestations a
                 ON a.id = e.action_attestation_id
              WHERE e.output_event_id IN ({placeholders})
              ORDER BY event_id, src"
        );
        let mut query = sqlx::query(&sql);
        for id in chunk {
            query = query.bind(id);
        }
        for id in chunk {
            query = query.bind(id);
        }
        for row in query.fetch_all(db.write_pool()).await? {
            let event_id: String = row.try_get("event_id")?;
            if attested.contains_key(&event_id) {
                continue;
            }
            let channel: Option<String> = row.try_get("channel").ok().flatten();
            let executor_kind: Option<String> = row.try_get("executor_kind").ok().flatten();
            let attestation_id: String = row.try_get("attestation_id")?;
            attested.insert(event_id, (channel, executor_kind, attestation_id));
        }
    }
    // Latest validity per attestation; invalidated collapses to unknown.
    let mut invalidated: HashSet<String> = HashSet::new();
    let attestation_ids: Vec<String> = attested
        .values()
        .map(|(_, _, id)| id.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    for chunk in attestation_ids.chunks(200) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
        let sql = format!(
            "SELECT attestation_id, status FROM provenance_attestation_validity_events
              WHERE attestation_id IN ({placeholders})
              ORDER BY attestation_id, ordinal DESC"
        );
        let mut query = sqlx::query(&sql);
        for id in chunk {
            query = query.bind(id);
        }
        let mut seen: HashSet<String> = HashSet::new();
        for row in query.fetch_all(db.write_pool()).await? {
            let id: String = row.try_get("attestation_id")?;
            if !seen.insert(id.clone()) {
                continue;
            }
            let status: String = row.try_get("status")?;
            if status == "invalidated" {
                invalidated.insert(id);
            }
        }
    }
    let mut map = HashMap::new();
    for event_id in event_ids {
        let provenance = match attested.get(event_id) {
            Some((channel, executor_kind, attestation_id))
                if !invalidated.contains(attestation_id) =>
            {
                provenance_for_change(
                    Channel::from_stored(channel.as_deref()),
                    true,
                    executor_kind.clone(),
                )
            }
            _ => provenance_for_change(Channel::Unknown, false, None),
        };
        map.insert(event_id.clone(), provenance);
    }
    Ok(map)
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
    /// Select the retained overlap-notice evaluation instead of ordinary run
    /// activity. Kept behind this explicit nested selector so existing calls
    /// and their response shape remain byte-for-byte unchanged.
    #[serde(default)]
    overlap_evaluation: Option<OverlapEvaluationArgs>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OverlapEvaluationScope {
    Own,
    Workspace,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OverlapEvaluationArgs {
    scope: OverlapEvaluationScope,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkOverlapEmission {
    kind: String,
    version: i64,
    surface: String,
    anchors: Vec<WorkOverlapEmissionAnchor>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkOverlapEmissionAnchor {
    record_id: String,
    overlap_record_ids: Vec<String>,
    overlap_item_count: i64,
    overlap_total_count: i64,
    truncated: bool,
}

struct RetainedOverlapNotice {
    seq: i64,
    id: String,
    run_key: Option<String>,
    actor: String,
    ended_at: String,
    emission: WorkOverlapEmission,
}

#[derive(Default)]
struct OverlapOutcomeCounts {
    mature: i64,
    pending: i64,
    released: i64,
    coordinated: i64,
    proceeded: i64,
    no_observed_outcome: i64,
}

const OVERLAP_OBSERVATION_MINUTES: i64 = 30;

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

#[cfg(test)]
mod tab_change_deadline_tests {
    //! How `records.changes.v1` settles a step once its deadline passes.

    use super::{deadline_step, is_sqlite_interrupt, DeadlineStep};
    use crate::error::{Error, Result};

    /// A real `SQLITE_INTERRUPT`, raised by a progress handler that refuses
    /// to continue, as the walk's own handler does past its deadline.
    async fn interrupted() -> Error {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut connection = db.write_pool().acquire().await.unwrap();
        connection
            .lock_handle()
            .await
            .unwrap()
            .set_progress_handler(1, || false);
        let error = sqlx::query_scalar::<_, i64>(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 100000)
             SELECT count(*) FROM n",
        )
        .fetch_one(&mut *connection)
        .await
        .unwrap_err();
        connection
            .lock_handle()
            .await
            .unwrap()
            .remove_progress_handler();
        Error::from(error)
    }

    fn cut<T>(step: Result<DeadlineStep<T>>) -> bool {
        matches!(step, Ok(DeadlineStep::Cut))
    }

    #[tokio::test]
    async fn only_the_armed_handlers_interrupt_past_the_deadline_cuts_a_page() {
        let interrupt = interrupted().await;
        assert!(is_sqlite_interrupt(&interrupt), "{interrupt:?}");
        let other = || Error::engine("no such index: idx_content_events_record_changes");
        assert!(!is_sqlite_interrupt(&other()));

        // Past the deadline with the handler armed: the handler's interrupt,
        // and a step that finished late, are cut; anything else propagates.
        assert!(cut(deadline_step::<()>(
            Err(interrupted().await),
            true,
            true
        )));
        assert!(cut(deadline_step(Ok(1), true, true)));
        assert!(deadline_step::<()>(Err(other()), true, true).is_err());
        // Without the armed handler, or before the deadline, nothing is cut:
        // failures propagate, including an interrupt nobody asked for.
        assert!(deadline_step::<()>(Err(interrupted().await), false, true).is_err());
        assert!(deadline_step::<()>(Err(interrupted().await), true, false).is_err());
        assert!(deadline_step::<()>(Err(other()), false, false).is_err());
        assert!(matches!(
            deadline_step(Ok(1), false, true),
            Ok(DeadlineStep::Done(1))
        ));
    }
}

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
    let claim_payload = payload.get("claimed_by_account").is_some()
        || payload.get("claimed_run_key").is_some()
        || payload.get("released_from_run_key").is_some();
    let claim_holder_visible = event.actor.as_deref() == Some(caller.credential());
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
                    match redaction_key_rule(key, claim_holder_visible) {
                        RedactionKeyRule::Erase => *child = Value::Null,
                        RedactionKeyRule::CheckReference => {
                            if let Some(id) = child.as_str() {
                                if !can_record(db, caller, id, Capability::View).await? {
                                    *child = Value::Null;
                                }
                            }
                        }
                        RedactionKeyRule::Descend => stack.push(child),
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
    if events::HISTORY_HIDDEN_EVENT_TYPES.contains(&event.event_type.as_str()) {
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
    if events::HISTORY_HIDDEN_EVENT_TYPES.contains(&event.event_type.as_str()) {
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
    if let Some(walk) = redact_event_actor_in(tx, caller, disclosure, event).await? {
        redact_event_payload_in(tx, caller, event, walk).await?;
    }
    Ok(())
}

/// A parsed payload awaiting [`redact_event_payload_in`], and how that walk
/// treats claim keys for this viewer.
pub(super) struct PayloadRedaction {
    pub(super) payload: Value,
    pub(super) claim_holder_visible: bool,
}

/// The first half of [`redact_event_in`]: the canvas summary and the actor
/// rule. Returns the payload walk still to do, or `None` when there is none
/// (a trusted local caller's events are not redacted; an event without a
/// parseable payload has nothing to walk, and an unparseable one is dropped).
pub(super) async fn redact_event_actor_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    disclosure: &mut ActorDisclosure,
    event: &mut EventRow,
) -> Result<Option<PayloadRedaction>> {
    crate::canvas::summarise_event_row(event);
    if super::is_legacy_local(caller) {
        return Ok(None);
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
        return Ok(None);
    };
    let Ok(payload) = serde_json::from_str::<Value>(raw) else {
        event.payload = None;
        return Ok(None);
    };
    let claim_payload = payload.get("claimed_by_account").is_some()
        || payload.get("claimed_run_key").is_some()
        || payload.get("released_from_run_key").is_some();
    let claim_holder_visible = event.actor.as_deref() == Some(caller.credential());
    if claim_payload && !claim_holder_visible {
        event.run_key = None;
        event.parent_key = None;
        event.intent = None;
    }
    Ok(Some(PayloadRedaction {
        payload,
        claim_holder_visible,
    }))
}

/// The second half of [`redact_event_in`]: walk the payload by
/// [`redaction_key_rule`], checking the viewer's access to each reference.
pub(super) async fn redact_event_payload_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    event: &mut EventRow,
    walk: PayloadRedaction,
) -> Result<()> {
    let PayloadRedaction {
        mut payload,
        claim_holder_visible,
    } = walk;
    let mut stack = vec![&mut payload];
    while let Some(value) = stack.pop() {
        match value {
            Value::Object(object) => {
                for (key, child) in object.iter_mut() {
                    match redaction_key_rule(key, claim_holder_visible) {
                        RedactionKeyRule::Erase => *child = Value::Null,
                        RedactionKeyRule::CheckReference => {
                            if let Some(id) = child.as_str() {
                                if !super::can_record_in(tx, caller, id, Capability::View).await? {
                                    *child = Value::Null;
                                }
                            }
                        }
                        RedactionKeyRule::Descend => stack.push(child),
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

/// What payload redaction does beneath one object key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RedactionKeyRule {
    /// The value is replaced by null, unread: identity keys always, and
    /// claim keys unless the viewer is the claim's holder.
    Erase,
    /// A text value is a record reference, kept only if the viewer may see
    /// that record. Nothing beneath it is walked.
    CheckReference,
    /// The value is walked like the rest of the payload.
    Descend,
}

/// The one rule payload redaction applies per key, shared by every walk
/// that must agree with it.
pub(super) fn redaction_key_rule(key: &str, claim_holder_visible: bool) -> RedactionKeyRule {
    let identity_key = matches!(key, "actor" | "account_id" | "email" | "owner_id");
    let record_key = key == "id" || key.ends_with("_id") || matches!(key, "owner" | "home");
    let claim_identity_key = matches!(
        key,
        "claimed_by_account" | "claimed_run_key" | "released_from_run_key"
    );
    if identity_key || (claim_identity_key && !claim_holder_visible) {
        RedactionKeyRule::Erase
    } else if record_key {
        RedactionKeyRule::CheckReference
    } else {
        RedactionKeyRule::Descend
    }
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
    let claim_payload = payload.get("claimed_by_account").is_some()
        || payload.get("claimed_run_key").is_some()
        || payload.get("released_from_run_key").is_some();
    let claim_holder_visible = event.actor.as_deref() == Some(caller.credential());
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
    let event_ids = matched_events
        .iter()
        .map(|event| event.id.clone())
        .collect::<Vec<_>>();
    let provenance = change_provenance_map(&db, &event_ids).await?;
    let mut groups: Vec<ChangeGroup> = Vec::new();
    let mut group_indexes: HashMap<ChangeGroupKey, usize> = HashMap::new();
    for (event, families) in matched {
        let (channel, _, executor_kind, _) = provenance
            .get(&event.id)
            .cloned()
            .unwrap_or_else(|| provenance_for_change(Channel::Unknown, false, None));
        let key = ChangeGroupKey {
            record_id: event.record_id.clone(),
            actor: event.actor.clone(),
            run_key: event.run_key.clone(),
            channel,
            executor_kind,
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
            let channel_assurance = if key.channel == "unknown" {
                "unknown_or_withheld"
            } else {
                "server_observed"
            };
            let executor_assurance = if key.executor_kind.is_some() {
                "engine_attested"
            } else {
                "unknown_or_withheld"
            };
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
                channel_assurance,
                executor_assurance,
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
                "channel": {"kind": group.key.channel, "assurance": group.channel_assurance},
                "executor": {"kind": group.key.executor_kind, "assurance": group.executor_assurance},
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

/// Read-tier form of [`require_public_history_record`]. Byte-identical logic
/// on the physically read-only pool, so `get_history`'s admission prologue
/// does not queue on the serialised writer. The shared `Db`-taking form stays
/// on the write pool for `whats_changed` until that handler migrates.
async fn require_public_history_record_in_pool(
    pool: &sqlx::SqlitePool,
    caller: &Caller,
    tool: &str,
    record_id: &str,
) -> Result<()> {
    super::require_record_in_pool(pool, caller, tool, record_id, Capability::View).await?;
    let acknowledgement = crate::query::acknowledgement_predicate("r");
    let hidden_acknowledgement: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM records r WHERE r.id=? AND {acknowledgement})"
    ))
    .bind(record_id)
    .fetch_one(pool)
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
        require_public_history_record_in_pool(db.pool(), &caller, "get_history", record_id).await?;
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
    // Resolve the database identity before taking the read snapshot below.
    // `database_id` itself acquires a read-pool connection on a cold memo, so
    // calling it while this snapshot is held would nest two checkouts of the
    // same 5-connection pool and can deadlock five concurrent callers.
    let local_database_id = crate::identity::database_id(&db).await?;
    let mut cursor = args.after_seq;
    let mut selected = Vec::new();
    let mut exhausted = false;
    let mut actor_disclosure = ActorDisclosure::default();
    // One physically read-only snapshot for the whole page walk. Every page
    // fetch and per-event visibility/redaction check here observes committed
    // state only, so none depends on the write pool's read-your-writes
    // snapshot within this call.
    let mut snapshot = db.pool().begin().await?;
    let result = async {
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
                    events::events_for_run_ordered_in(
                        &mut snapshot,
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
                        events::events_for_record_ordered_in(
                            &mut snapshot,
                            record_id,
                            cursor,
                            1000,
                            args.order.event_order(),
                        )
                        .await?
                    }
                    None => {
                        events::all_events_ordered_in(
                            &mut snapshot,
                            cursor,
                            1000,
                            args.order.event_order(),
                        )
                        .await?
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
                    && !can_record_in(&mut snapshot, &caller, &event.record_id, Capability::View)
                        .await?
                {
                    continue;
                }
                if !event_is_visible_in(&mut snapshot, &caller, &event).await? {
                    continue;
                }
                redact_event_in(&mut snapshot, &caller, &mut actor_disclosure, &mut event).await?;
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
                shape_history_event(event_to_value(event, &actor_names), args.detail)
            }).collect::<Vec<_>>(),
            "next_after_local_seq": if exhausted { None } else { cursor },
            "order": args.order,
            "representation": history_representation(args.detail),
        }))
    }
    .await;
    snapshot.rollback().await?;
    result
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
    // The record-history walk is non-mutating; run it on the physically
    // read-only pool's snapshot so it never waits on the serialised writer.
    let mut snapshot = db.pool().begin().await?;
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

/// Longest scalar value, in characters, a `records.changes.v1` page carries
/// for one side of one change. Longer values are cut and flagged.
pub(crate) const TAB_CHANGE_VALUE_MAX_CHARS: usize = 256;

/// Longest field name, in characters, a `records.changes.v1` page carries in
/// `changed_fields` or `changes[].field`. Facet keys are otherwise unbounded;
/// a longer name is cut and the event flagged `fields_truncated`.
pub(crate) const TAB_CHANGE_FIELD_MAX_CHARS: usize = 256;

/// Longest `reason`, in characters, a `records.changes.v1` page carries.
pub(crate) const TAB_CHANGE_REASON_MAX_CHARS: usize = 1024;

/// Rows fetched per step, so a record whose events carry very large bodies
/// never holds more than a few of them at once.
const TAB_CHANGE_SCAN_WINDOW: usize = 16;

/// The stored event types that can carry a scalar or body change, as
/// [`changed_fields_for_payload`] names them. A look-back reads payloads of
/// these only.
const TAB_CHANGE_FIELD_EVENT_TYPES: &[&str] = &[
    "record.created",
    "record.updated",
    "receipt.committed.v1",
    "record.type_corrected.v1",
    "facet.set",
    "facet.unset",
];

/// Largest stored payload, in bytes, one `records.changes.v1` event may
/// carry and still be processed. It measures raw stored bytes, before
/// redaction, so a larger one is not read at all and its event arrives as an
/// `unprocessed` placeholder with `created_at: null` for every viewer. That
/// discloses one accepted fact, that the raw payload exceeds this; a
/// processed event's `payload_bytes` is the viewer's redacted size.
pub const TAB_CHANGE_MAX_PAYLOAD_BYTES: i64 = 8 * 1024 * 1024;

/// Most record references (`id`, `*_id`, `owner`, `home` keys holding text)
/// one event's payload may carry and still be processed. Redaction checks
/// the viewer's access to each, one authorization query apiece, so an event
/// with more arrives as an `unprocessed` placeholder instead.
pub const TAB_CHANGE_MAX_REFERENCES: usize = 256;

/// SQLite VM instructions between deadline checks in the progress handler.
const TAB_CHANGE_PROGRESS_OPS: i32 = 1000;

/// The work one `records.changes.v1` read may do.
///
/// Every row it examines is a row the viewer can see (see
/// [`events::field_change_rows_in`]), so none of these can be spent, or
/// seen to be spent, on hidden history. `scan_rows` and `lookback_rows`
/// bound the rows examined. `deadline` bounds time: it is checked before
/// every event, and a SQLite progress handler interrupts any statement still
/// running when it passes.
///
/// Running out is reported, never hidden: a page walk that stops early is
/// `complete: false` with a cursor after the last event it carries, and a
/// look-back that stops early leaves the values it did not find
/// `before_known: false`. A page always processes its first row whatever
/// the budget, so paging always progresses; that row's work is bounded by
/// [`TAB_CHANGE_MAX_PAYLOAD_BYTES`] and [`TAB_CHANGE_MAX_REFERENCES`].
#[derive(Clone, Copy, Debug)]
pub struct TabChangeBudget {
    /// Rows the page walk may examine.
    pub scan_rows: usize,
    /// Rows the look-back may examine past the page.
    pub lookback_rows: usize,
    /// Time after which no further statement or event is started.
    pub deadline: std::time::Duration,
}

impl TabChangeBudget {
    pub const DEFAULT: Self = Self {
        scan_rows: 1024,
        lookback_rows: 256,
        deadline: std::time::Duration::from_millis(1500),
    };
}

/// One page of a record's changes, newest first, shaped for a tab: see
/// [`tab_record_changes_in`].
pub(crate) struct TabRecordChangesPage {
    /// `(event id, shaped event)`, newest first.
    pub(crate) events: Vec<(String, Value)>,
    /// The id of the page's last event, when older events may remain.
    /// `None` means the record's history is exhausted.
    pub(crate) resume_after: Option<String>,
}

/// One scalar a field-changing event assigns.
struct ScalarAssignment {
    /// The name `changed_fields` gives it: `name`, `facet:lifecycle`, ...
    field: String,
    /// The record state it writes. A spine facet and its record column are
    /// one state, so `facet:lifecycle` and `lifecycle` share `lifecycle`.
    state: String,
    value: Value,
    /// The value it replaces, when the event itself states it
    /// (`record.type_corrected.v1`).
    from: Option<Value>,
    /// A valid-time observation that leaves the current value alone.
    observation_only: bool,
}

/// Which states an event writes that could not be processed.
enum UnprocessedWrites {
    /// These states, with values that are not known.
    States(Vec<String>),
    /// Not known: its payload was not read.
    Unknown,
}

/// One event of a page, before the page's before-values are known.
enum TabChangeEvent {
    Processed {
        event_id: String,
        shaped: Value,
        /// For `record.created`, every scalar state as the projector stores it.
        creation: Option<Vec<(String, Value)>>,
        assignments: Vec<ScalarAssignment>,
        body_bytes: Option<u64>,
    },
    /// An event over the per-event work bounds: shown as a placeholder, and
    /// what it writes becomes unknown.
    Unprocessed {
        event_id: String,
        event_type: String,
        /// `None` for a payload over the byte cap: its time is stored after
        /// it, and is not read.
        created_at: Option<String>,
        writes: UnprocessedWrites,
    },
}

/// Record state as a page replays it: a known value, `None` for a value
/// that cannot be known, and absent for one not yet seen.
#[derive(Default)]
struct TabChangeState {
    values: HashMap<String, Option<Value>>,
    /// The record's creation is behind this point: an unseen state is its
    /// creation default, null.
    origin_known: bool,
    /// An event whose writes are unknown is behind this point: an unseen
    /// state may have been written by it.
    clouded: bool,
}

impl TabChangeState {
    /// The value `state` holds here, or `None` when it cannot be known.
    fn value(&self, state: &str) -> Option<Value> {
        match self.values.get(state) {
            Some(value) => value.clone(),
            None if self.clouded => None,
            None if self.origin_known => Some(Value::Null),
            None => None,
        }
    }
}

/// How many reference checks redaction may make in `payload` for this
/// viewer, stopping once past `cap`: every key [`redaction_key_rule`] marks
/// as a reference, beneath every key it walks for this viewer (so beneath a
/// claim key only when the viewer holds the claim). A reference key whose
/// value is not text costs redaction nothing, but is counted anyway, so the
/// count depends only on keys, which redaction always leaves in place:
/// everything it reads is visible in the same viewer's `get_history`.
fn payload_reference_count(payload: &Value, claim_holder_visible: bool, cap: usize) -> usize {
    let mut count = 0usize;
    let mut stack = vec![payload];
    while let Some(value) = stack.pop() {
        match value {
            Value::Object(object) => {
                for (key, child) in object {
                    match redaction_key_rule(key, claim_holder_visible) {
                        RedactionKeyRule::Erase => {}
                        RedactionKeyRule::CheckReference => {
                            count += 1;
                            if count > cap {
                                return count;
                            }
                        }
                        RedactionKeyRule::Descend => stack.push(child),
                    }
                }
            }
            Value::Array(values) => stack.extend(values.iter()),
            _ => {}
        }
    }
    count
}

/// The scalar record state a `record.created` event leaves, as
/// `apply_record_created` stores it whichever fields the payload names: an
/// absent or null name is empty text, and an absent type, lifecycle or
/// maturity is null. Facets start unset.
fn creation_state(payload: &Value) -> Vec<(String, Value)> {
    let field = |name: &str| payload.get(name).cloned().unwrap_or(Value::Null);
    let name = match field("name") {
        Value::Null => Value::String(String::new()),
        name => name,
    };
    vec![
        ("name".into(), name),
        ("type".into(), field("type")),
        ("kind".into(), field("kind")),
        ("lifecycle".into(), field("lifecycle")),
        ("maturity".into(), field("maturity")),
    ]
}

/// The scalars `records.changes.v1` reports values for, by the names
/// `changed_fields` uses. Owner and persistence are named in
/// `changed_fields` but carry no values here: an owner is a person record
/// the viewer may not see.
fn scalar_assignments(event_type: &str, payload: &Value) -> Vec<ScalarAssignment> {
    let assign = |field: &str, value: Value| ScalarAssignment {
        field: field.to_string(),
        state: field.to_string(),
        value,
        from: None,
        observation_only: false,
    };
    match event_type {
        "record.created" => {
            let Some(object) = payload.as_object() else {
                return Vec::new();
            };
            creation_state(payload)
                .into_iter()
                .filter(|(field, _)| object.contains_key(field))
                .map(|(field, value)| assign(&field, value))
                .collect()
        }
        "record.updated" | "receipt.committed.v1" => {
            let Some(object) = payload.as_object() else {
                return Vec::new();
            };
            ["name", "lifecycle", "maturity", "kind"]
                .into_iter()
                .filter_map(|field| Some(assign(field, object.get(field)?.clone())))
                .collect()
        }
        "record.type_corrected.v1" => ["kind", "type"]
            .into_iter()
            .map(|field| ScalarAssignment {
                from: Some(payload["from"][field].clone()),
                ..assign(field, payload["to"][field].clone())
            })
            .collect(),
        "facet.set" | "facet.unset" => {
            let Some(key) = payload.get("key").and_then(Value::as_str) else {
                return Vec::new();
            };
            let state = match key {
                "owner" | "persistence" => return Vec::new(),
                "lifecycle" | "maturity" => key.to_string(),
                _ => format!("facet:{key}"),
            };
            let value = if event_type == "facet.set" {
                payload.get("value").cloned().unwrap_or(Value::Null)
            } else {
                Value::Null
            };
            vec![ScalarAssignment {
                field: format!("facet:{key}"),
                state,
                value,
                from: None,
                observation_only: payload
                    .get("observation_only")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            }]
        }
        _ => Vec::new(),
    }
}

/// UTF-8 bytes of the body an event writes, if it writes one. Text counts
/// as itself; anything else as the text the projector stores for it.
fn body_bytes(event_type: &str, payload: &Value) -> Option<u64> {
    if !matches!(
        event_type,
        "record.created" | "record.updated" | "receipt.committed.v1"
    ) {
        return None;
    }
    Some(match payload.get("body")? {
        Value::Null => 0,
        Value::String(text) => text.len() as u64,
        other => other.to_string().len() as u64,
    })
}

/// `value` as a tab receives it: null, or text of at most
/// [`TAB_CHANGE_VALUE_MAX_CHARS`] characters, and whether it was cut.
/// Anything that is not text arrives as its JSON text.
fn bounded_scalar(value: &Value) -> (Value, bool) {
    let text = match value {
        Value::Null => return (Value::Null, false),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    bounded_text(&text, TAB_CHANGE_VALUE_MAX_CHARS)
}

fn bounded_text(text: &str, max_chars: usize) -> (Value, bool) {
    match text.char_indices().nth(max_chars) {
        Some((end, _)) => (Value::String(text[..end].to_string()), true),
        None => (Value::String(text.to_string()), false),
    }
}

/// The viewer may read `record_id`'s history: exactly `get_history`'s own
/// View and acknowledgement refusal, message included.
pub(crate) async fn require_tab_history_record_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    record_id: &str,
) -> Result<()> {
    super::require_record_in(tx, caller, "get_history", record_id, Capability::View).await?;
    let acknowledgement = crate::query::acknowledgement_predicate("r");
    let hidden_acknowledgement: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM records r WHERE r.id=? AND {acknowledgement})"
    ))
    .bind(record_id)
    .fetch_one(&mut **tx)
    .await?;
    if hidden_acknowledgement {
        return Err(Error::engine(format!(
            "get_history: record {record_id} does not exist"
        )));
    }
    Ok(())
}

/// The internal position of one of the record's own events, for resuming a
/// `records.changes.v1` page after it. `None` when no such event belongs to
/// the record. The position never leaves the engine, and the caller must
/// only ask about an event id it sealed itself.
pub(crate) async fn record_event_position_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    record_id: &str,
    event_id: &str,
) -> Result<Option<i64>> {
    Ok(
        sqlx::query_scalar("SELECT seq FROM content_events WHERE id = ? AND record_id = ?")
            .bind(event_id)
            .bind(record_id)
            .fetch_optional(&mut **tx)
            .await?,
    )
}

/// One page of a record's history as the `records.changes.v1` tab read
/// shows it, newest first, on the caller's transaction.
///
/// The page is `get_history {record_id, detail: metadata}` under the
/// viewer, less `occurrence.bound.v1` events, which carry no field change:
/// the same View and acknowledgement refusal (with `get_history`'s own
/// message), the same visible events, the same `redact_event_in` actor and
/// payload rule (an actor the viewer may not see is null, with its run), and
/// `changed_fields`, `reason` and payload size taken from
/// [`shape_history_event`] itself. Visibility is applied in SQL before a
/// row is examined (see [`events::field_change_rows_in`]), so nothing about
/// hidden events, their number included, shapes a page. Payloads never
/// reach the tab. What it adds:
///
/// * **Scalar before/after** for `name`, `lifecycle`, `maturity`, `kind`,
///   `type` and non-spine `facet:<key>` values, each cut at
///   [`TAB_CHANGE_VALUE_MAX_CHARS`] and flagged. Before-values come from the
///   record's own events only, through the same redaction as the page: the
///   older events in this page, then a look-back of at most
///   [`TabChangeBudget::lookback_rows`] earlier rows. There is no log
///   replay. A before-value not found that way is reported unknown.
/// * **Body changes** as their size in bytes, never their text.
/// * **Bounded work** per [`TabChangeBudget`]; an event over the per-event
///   bounds arrives as `{event_id, type, created_at, unprocessed: true}`.
///
/// Nothing positional is returned. The caller resumes from an event id, via
/// [`record_event_position_in`].
pub(crate) async fn tab_record_changes_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    record_id: &str,
    after: Option<i64>,
    limit: usize,
    budget: TabChangeBudget,
) -> Result<TabRecordChangesPage> {
    require_tab_history_record_in(tx, caller, record_id).await?;
    let deadline = std::time::Instant::now() + budget.deadline;
    let result =
        tab_record_changes_walk(tx, caller, record_id, after, limit, budget, deadline).await;
    // The handler must not outlive this read: the caller goes on to roll the
    // transaction back on this connection.
    tx.lock_handle().await?.remove_progress_handler();
    result
}

async fn tab_record_changes_walk(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    record_id: &str,
    after: Option<i64>,
    limit: usize,
    budget: TabChangeBudget,
    deadline: std::time::Instant,
) -> Result<TabRecordChangesPage> {
    let out_of_time = || std::time::Instant::now() >= deadline;

    let mut disclosure = ActorDisclosure::default();
    let no_names = HashMap::new();
    let mut page: Vec<TabChangeEvent> = Vec::new();
    let mut cursor = after;
    let mut examined = 0usize;
    let mut exhausted = false;
    let mut deadline_armed = false;
    'scan: while page.len() < limit {
        if examined > 0 && (examined >= budget.scan_rows || out_of_time()) {
            break;
        }
        // The page's first row is read on its own and without the deadline,
        // so every page carries at least one event. Every later statement
        // runs under the progress handler.
        let window = if examined == 0 {
            1
        } else {
            if !deadline_armed {
                tx.lock_handle()
                    .await?
                    .set_progress_handler(TAB_CHANGE_PROGRESS_OPS, move || {
                        std::time::Instant::now() < deadline
                    });
                deadline_armed = true;
            }
            TAB_CHANGE_SCAN_WINDOW.min(budget.scan_rows - examined)
        };
        let rows = events::field_change_rows_in(
            tx,
            record_id,
            cursor,
            window as i64,
            None,
            TAB_CHANGE_MAX_PAYLOAD_BYTES,
        )
        .await;
        let rows = match deadline_step(rows, deadline_armed, out_of_time())? {
            DeadlineStep::Done(rows) => rows,
            DeadlineStep::Cut => break,
        };
        let fetched = rows.len();
        if fetched < window {
            exhausted = true;
        }
        for (index, row) in rows.into_iter().enumerate() {
            if examined > 0 && out_of_time() {
                exhausted = false;
                break 'scan;
            }
            let seq = row.event.local_seq;
            let processed = tab_change_event(tx, caller, &mut disclosure, &no_names, row).await;
            match deadline_step(processed, deadline_armed, out_of_time())? {
                DeadlineStep::Done(processed) => page.push(processed),
                DeadlineStep::Cut => {
                    exhausted = false;
                    break 'scan;
                }
            }
            examined += 1;
            cursor = Some(seq);
            if page.len() == limit {
                // Complete only if this was the record's oldest row.
                exhausted = exhausted && index + 1 == fetched;
                break 'scan;
            }
        }
        if exhausted {
            break;
        }
    }

    // Walk the page oldest first, noting each state it reads before any
    // event in the page has written it: those need a look-back.
    let mut written: HashSet<String> = HashSet::new();
    let mut needed: HashSet<String> = HashSet::new();
    let mut settled = false;
    for change in page.iter().rev() {
        match change {
            TabChangeEvent::Processed {
                creation,
                assignments,
                ..
            } => {
                settled |= creation.is_some();
                for assignment in assignments {
                    if !settled && assignment.from.is_none() && !written.contains(&assignment.state)
                    {
                        needed.insert(assignment.state.clone());
                    }
                    if !assignment.observation_only {
                        written.insert(assignment.state.clone());
                    }
                }
            }
            TabChangeEvent::Unprocessed {
                event_type, writes, ..
            } => {
                settled |= event_type == "record.created";
                match writes {
                    UnprocessedWrites::States(states) => written.extend(states.iter().cloned()),
                    // Everything after it is unknown or written after it.
                    UnprocessedWrites::Unknown => settled = true,
                }
            }
        }
    }

    // The look-back reads the record's own earlier rows through the same
    // redaction as the page, so a before-value is whatever the viewer would
    // have seen had the page been long enough to hold the event that wrote
    // it.
    let mut state = TabChangeState::default();
    if !needed.is_empty() && !exhausted {
        let mut before = cursor;
        let mut looked = 0usize;
        'lookback: while looked < budget.lookback_rows && !out_of_time() {
            if !deadline_armed {
                tx.lock_handle()
                    .await?
                    .set_progress_handler(TAB_CHANGE_PROGRESS_OPS, move || {
                        std::time::Instant::now() < deadline
                    });
                deadline_armed = true;
            }
            let window = TAB_CHANGE_SCAN_WINDOW.min(budget.lookback_rows - looked);
            let rows = events::field_change_rows_in(
                tx,
                record_id,
                before,
                window as i64,
                Some(TAB_CHANGE_FIELD_EVENT_TYPES),
                TAB_CHANGE_MAX_PAYLOAD_BYTES,
            )
            .await;
            let rows = match deadline_step(rows, deadline_armed, out_of_time())? {
                DeadlineStep::Done(rows) => rows,
                DeadlineStep::Cut => break,
            };
            let fetched = rows.len();
            for row in rows {
                if out_of_time() {
                    break 'lookback;
                }
                looked += 1;
                before = Some(row.event.local_seq);
                if !TAB_CHANGE_FIELD_EVENT_TYPES.contains(&row.event.event_type.as_str()) {
                    continue;
                }
                let created = row.event.event_type == "record.created";
                let processed = tab_change_event(tx, caller, &mut disclosure, &no_names, row).await;
                let processed = match deadline_step(processed, deadline_armed, out_of_time())? {
                    DeadlineStep::Done(processed) => processed,
                    DeadlineStep::Cut => break 'lookback,
                };
                match processed {
                    TabChangeEvent::Processed {
                        creation,
                        assignments,
                        ..
                    } => {
                        if let Some(creation) = creation {
                            for (key, value) in creation {
                                if needed.remove(&key) {
                                    state.values.insert(key, Some(value));
                                }
                            }
                            state.origin_known = true;
                            break 'lookback;
                        }
                        for assignment in assignments {
                            if !assignment.observation_only && needed.remove(&assignment.state) {
                                state
                                    .values
                                    .insert(assignment.state, Some(assignment.value));
                            }
                        }
                    }
                    TabChangeEvent::Unprocessed { writes, .. } => match writes {
                        UnprocessedWrites::States(states) => {
                            for key in states {
                                if needed.remove(&key) {
                                    state.values.insert(key, None);
                                }
                            }
                            if created {
                                state.origin_known = true;
                                break 'lookback;
                            }
                        }
                        // Whatever is still needed may have been written by
                        // it: none of it can be known.
                        UnprocessedWrites::Unknown => break 'lookback,
                    },
                }
                if needed.is_empty() {
                    break 'lookback;
                }
            }
            if fetched < window {
                break;
            }
        }
    }

    // Replay the page oldest first over what the look-back found.
    let mut shaped_by_event: Vec<(String, Value)> = Vec::with_capacity(page.len());
    for change in page.iter().rev() {
        let (event_id, shaped, creation, assignments, body_bytes) = match change {
            TabChangeEvent::Unprocessed {
                event_id,
                event_type,
                created_at,
                writes,
            } => {
                match writes {
                    UnprocessedWrites::States(states) => {
                        for key in states {
                            state.values.insert(key.clone(), None);
                        }
                    }
                    UnprocessedWrites::Unknown => {
                        state.values.clear();
                        state.clouded = true;
                    }
                }
                state.origin_known |= event_type == "record.created";
                shaped_by_event.push((
                    event_id.clone(),
                    json!({
                        "event_id": event_id,
                        "type": event_type,
                        "created_at": created_at,
                        "unprocessed": true,
                    }),
                ));
                continue;
            }
            TabChangeEvent::Processed {
                event_id,
                shaped,
                creation,
                assignments,
                body_bytes,
            } => (event_id, shaped, creation, assignments, body_bytes),
        };
        let mut changes = Vec::new();
        let mut fields_truncated = false;
        for assignment in assignments {
            let before = if creation.is_some() {
                Some(Value::Null)
            } else if let Some(from) = &assignment.from {
                Some(from.clone())
            } else {
                state.value(&assignment.state)
            };
            let (before_value, before_truncated) =
                before.as_ref().map_or((Value::Null, false), bounded_scalar);
            let (after_value, after_truncated) = bounded_scalar(&assignment.value);
            let (field, cut) = bounded_text(&assignment.field, TAB_CHANGE_FIELD_MAX_CHARS);
            fields_truncated |= cut;
            changes.push(json!({
                "field": field,
                "before": before_value,
                "before_known": before.is_some(),
                "before_truncated": before_truncated,
                "after": after_value,
                "after_truncated": after_truncated,
                "observation_only": assignment.observation_only,
            }));
        }
        if let Some(creation) = creation {
            state.values = creation
                .iter()
                .map(|(key, value)| (key.clone(), Some(value.clone())))
                .collect();
            state.origin_known = true;
            state.clouded = false;
        }
        for assignment in assignments {
            if !assignment.observation_only {
                state
                    .values
                    .insert(assignment.state.clone(), Some(assignment.value.clone()));
            }
        }
        if let Some(bytes) = body_bytes {
            changes.push(json!({"field": "body", "changed": true, "bytes": bytes}));
        }
        let (reason, reason_truncated) = match shaped.get("reason").and_then(Value::as_str) {
            Some(reason) => bounded_text(reason, TAB_CHANGE_REASON_MAX_CHARS),
            None => (Value::Null, false),
        };
        let changed_fields: Vec<Value> = shaped["changed_fields"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .map(|field| {
                let (field, cut) = bounded_text(
                    field.as_str().unwrap_or_default(),
                    TAB_CHANGE_FIELD_MAX_CHARS,
                );
                fields_truncated |= cut;
                field
            })
            .collect();
        shaped_by_event.push((
            event_id.clone(),
            json!({
                "event_id": event_id,
                "type": shaped["type"],
                "created_at": shaped["created_at"],
                "actor": shaped["actor"],
                "run_key": shaped["run_key"],
                "changed_fields": changed_fields,
                "fields_truncated": fields_truncated,
                "reason": reason,
                "reason_truncated": reason_truncated,
                "payload_bytes": shaped["payload_json_utf8_bytes"],
                "changes": changes,
            }),
        ));
    }
    shaped_by_event.reverse();
    if page.is_empty() && !exhausted {
        // Unreachable by construction (a page's first row is always
        // processed or its failure propagated), and never to be reported as
        // the end of history.
        return Err(Error::engine(
            "records.changes.v1: the page made no progress",
        ));
    }
    let resume_after = if exhausted {
        None
    } else {
        page.last().map(|change| change.event_id().to_string())
    };
    Ok(TabRecordChangesPage {
        events: shaped_by_event,
        resume_after,
    })
}

/// What became of one step of the walk once the deadline is taken into
/// account.
enum DeadlineStep<T> {
    Done(T),
    /// The deadline passed while the progress handler was armed: the step
    /// may have been interrupted part-way, so it is discarded and the page
    /// ends incomplete.
    Cut,
}

/// Settle one step of the walk. Only a step that ends after the deadline
/// with the progress handler armed can be cut, and only if it either
/// succeeded or failed with the handler's own `SQLITE_INTERRUPT`. A step
/// that finished late is discarded rather than trusted, because an
/// interrupted authorization check inside redaction reads as "no access".
/// Every other failure propagates, so no failure ever reads as the end of
/// history.
fn deadline_step<T>(
    result: Result<T>,
    armed: bool,
    past_deadline: bool,
) -> Result<DeadlineStep<T>> {
    if armed && past_deadline {
        return match result {
            Err(error) if !is_sqlite_interrupt(&error) => Err(error),
            _ => Ok(DeadlineStep::Cut),
        };
    }
    result.map(DeadlineStep::Done)
}

/// Whether `error` is SQLite's `SQLITE_INTERRUPT` (result code 9), which is
/// what a progress handler returning false raises.
fn is_sqlite_interrupt(error: &Error) -> bool {
    matches!(
        error,
        Error::Sqlx(sqlx::Error::Database(database))
            if database.code().as_deref() == Some("9")
    )
}

impl TabChangeEvent {
    fn event_id(&self) -> &str {
        match self {
            Self::Processed { event_id, .. } | Self::Unprocessed { event_id, .. } => event_id,
        }
    }
}

/// Process one visible row within the per-event bounds: redact it as
/// `get_history` does and derive what it changed, or, over the bounds,
/// describe it as unprocessed.
async fn tab_change_event(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    disclosure: &mut ActorDisclosure,
    no_names: &HashMap<String, String>,
    row: events::FieldChangeRow,
) -> Result<TabChangeEvent> {
    let mut event = row.event;
    let unprocessed = |event: &EventRow, writes| TabChangeEvent::Unprocessed {
        event_id: event.id.clone(),
        event_type: event.event_type.clone(),
        created_at: (!row.withheld).then(|| event.created_at.clone()),
        writes,
    };
    if row.withheld {
        return Ok(unprocessed(&event, UnprocessedWrites::Unknown));
    }
    // Redact as `redact_event_in` does, in its two halves, so the reference
    // cap is judged on exactly the walk this viewer's redaction would make.
    if let Some(walk) = redact_event_actor_in(tx, caller, disclosure, &mut event).await? {
        if payload_reference_count(
            &walk.payload,
            walk.claim_holder_visible,
            TAB_CHANGE_MAX_REFERENCES,
        ) > TAB_CHANGE_MAX_REFERENCES
        {
            // Which states it writes comes from its top-level keys, which
            // redaction never removes.
            let mut states: Vec<String> = scalar_assignments(&event.event_type, &walk.payload)
                .into_iter()
                .map(|assignment| assignment.state)
                .collect();
            if event.event_type == "record.created" {
                states.extend(
                    creation_state(&walk.payload)
                        .into_iter()
                        .map(|(key, _)| key),
                );
            }
            return Ok(unprocessed(&event, UnprocessedWrites::States(states)));
        }
        redact_event_payload_in(tx, caller, &mut event, walk).await?;
    }
    let payload: Value = event
        .payload
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or(Value::Null);
    Ok(TabChangeEvent::Processed {
        event_id: event.id.clone(),
        creation: (event.event_type == "record.created").then(|| creation_state(&payload)),
        assignments: scalar_assignments(&event.event_type, &payload),
        body_bytes: body_bytes(&event.event_type, &payload),
        shaped: shape_history_event(event_to_value(&event, no_names), HistoryDetail::Metadata),
    })
}

/// Opt-in oldest/newest visible-event attribution for `get_record` bylines.
///
/// Both ends run the same per-event pipeline as `get_history` on this
/// snapshot — `event_is_visible_in`, then `redact_event_in` under the
/// caller's shared disclosure memo, then snapshot-scoped actor-name
/// resolution — and shape the survivors with `detail: metadata`. So
/// "oldest"/"latest" mean oldest/newest *visible*, exactly as a
/// `limit: 1` `oldest_first`/`newest_first` metadata read would report them,
/// not raw `MIN`/`MAX(seq)` before visibility.
///
/// Each end advances in two-row raw windows (limit 1 plus the look-ahead row)
/// from its end, moving the keyset cursor past hidden events, so finding one
/// visible event never fetches a 1000-row full-payload page to discard. The
/// windows are bounded; the walk itself ends at the first visible event, so
/// its length is proportional to leading hidden events — the same traversal
/// cost profile as a `limit: 1` `get_history` read. The result is always
/// `Some`, even when both ends are null — presence of the summary on the
/// record is the capability signal, and null ends mean "no visible event".
pub(super) async fn history_summary_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    disclosure: &mut ActorDisclosure,
    record_id: &str,
) -> Result<read::HistorySummary> {
    let oldest = first_visible_in(
        tx,
        caller,
        disclosure,
        record_id,
        events::EventOrder::OldestFirst,
    )
    .await?;
    let latest = first_visible_in(
        tx,
        caller,
        disclosure,
        record_id,
        events::EventOrder::NewestFirst,
    )
    .await?;
    let shaped_inputs: Vec<EventRow> = oldest.clone().into_iter().chain(latest.clone()).collect();
    let actor_names = resolve_actor_names_in(tx, &shaped_inputs).await;
    let shape = |event: EventRow| {
        shape_history_event(
            event_to_value(&event, &actor_names),
            HistoryDetail::Metadata,
        )
    };
    Ok(read::HistorySummary {
        oldest: oldest.map(&shape),
        latest: latest.map(&shape),
    })
}

/// First visible event from one end of a record's stream on this snapshot.
///
/// Keyset-pages two-row raw windows (limit 1 plus look-ahead) from the given
/// end, advancing past hidden events exactly as the `get_history` traversal
/// does, and returns the first event that survives visibility, already
/// redacted. Ordinary records settle in one window per end; each further
/// window is one more leading hidden event. `None` means the end is
/// exhausted with nothing visible.
async fn first_visible_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    disclosure: &mut ActorDisclosure,
    record_id: &str,
    order: events::EventOrder,
) -> Result<Option<EventRow>> {
    const SUMMARY_SCAN: i64 = 1;
    let mut cursor: Option<i64> = None;
    loop {
        let page = events::events_for_record_ordered_in(tx, record_id, cursor, SUMMARY_SCAN, order)
            .await?;
        if page.events.is_empty() {
            return Ok(None);
        }
        for mut event in page.events {
            cursor = Some(event.local_seq);
            if !event_is_visible_in(tx, caller, &event).await? {
                continue;
            }
            redact_event_in(tx, caller, disclosure, &mut event).await?;
            return Ok(Some(event));
        }
        if page.next_after_seq.is_none() {
            return Ok(None);
        }
    }
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
            "completeness": if unavailable_reason.is_some() { "unavailable" } else { "retained_rows_only" },
        },
        "read_activity": read_activity,
    })
}

async fn get_run_activity(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: GetRunActivityArgs = parse_args("get_run_activity", arguments)?;
    if let Some(evaluation) = args.overlap_evaluation {
        if args.for_run.is_some()
            || args.include_child_runs.is_some()
            || args.cursor.is_some()
            || args.limit.is_some()
        {
            return Err(Error::engine(
                "get_run_activity: overlap_evaluation cannot be combined with for_run, \
                 include_child_runs, cursor, or limit",
            ));
        }
        return work_overlap_evaluation(&db, &caller, evaluation.scope).await;
    }
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
        // Ownership must not depend on retained read-log rows alone: capture
        // filtering (task 8a6377f PR A) drops disposable pure-read calls, so
        // a run with no retained read calls still owns its durable
        // `agent_runs` row and any declared `content_events`. Without the
        // durable route this check would report "run does not exist" for a
        // live read-only run — the DELETE-rows fork of audit increment 3.
        let owns_root = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM read_log_calls
               WHERE run_key = ? AND actor = ?)
                OR EXISTS(SELECT 1 FROM agent_runs
               WHERE run_key = ? AND account_id = ?)
                OR EXISTS(SELECT 1 FROM content_events
               WHERE run_key = ? AND actor = ?)",
        )
        .bind(run_key)
        .bind(caller.credential())
        .bind(run_key)
        .bind(caller.credential())
        .bind(run_key)
        .bind(caller.credential())
        .fetch_one(db.pool())
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
                dictionary.record_id AS touch_record_id,
                touch.interaction AS touch_interaction
           FROM selected_calls call
           LEFT JOIN read_log_touches touch ON touch.call_seq = call.seq
           LEFT JOIN read_log_record_ids dictionary ON dictionary.record_ref = touch.record_ref
          ORDER BY call.seq, dictionary.record_id, touch.interaction",
    )
    .bind(run_key)
    .bind(include_child_runs)
    .bind(include_child_runs)
    .bind(legacy_local)
    .bind(caller.credential())
    .fetch_all(db.pool())
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
        // A run may touch the same record thousands of times. Authorize the
        // distinct records once on a current snapshot, then retain every
        // historical interaction in the aggregate below. This is request-local:
        // the next poll still observes current revocations and admission rules.
        let mut touched_ids = HashSet::new();
        for row in &rows {
            if let Some(id) = row.try_get::<Option<String>, _>("touch_record_id")? {
                touched_ids.insert(id);
            }
        }
        let visible = if touched_ids.is_empty() {
            HashSet::new()
        } else {
            super::visible_ids_in_pool(db.pool(), &caller, touched_ids.into_iter().collect())
                .await?
        };

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
            if !visible.contains(&record_id) {
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

fn overlap_evaluation_unavailable(
    as_of: &str,
    scope: OverlapEvaluationScope,
    reason: &str,
) -> Value {
    json!({
        "view": "work_overlap_evaluation",
        "scope": match scope { OverlapEvaluationScope::Own => "own", OverlapEvaluationScope::Workspace => "workspace" },
        "as_of": as_of,
        "observation_window_seconds": OVERLAP_OBSERVATION_MINUTES * 60,
        "availability": {
            "status": "unavailable",
            "reason": reason,
            "complete_history": false,
            "retention": "The interaction log and its result annotations are disposable retained evidence, not canonical history."
        },
        "emissions": Value::Null,
        "claim_outcomes": Value::Null,
    })
}

fn is_explicit_coordination(action: &ObservedOverlapAction, eligible: &HashSet<String>) -> bool {
    let touches_eligible = action.touched.iter().any(|id| eligible.contains(id));
    match action.tool.as_str() {
        // A durable link written on either side of disclosed work is the v1
        // generic coordination primitive. Removal is material work instead.
        MANAGE_LINKS => {
            action.arguments.get("action").and_then(Value::as_str) == Some("add")
                && touches_eligible
        }
        // Handoff is a governed core kind. It qualifies only when the create
        // explicitly links the handoff to an anchor or disclosed overlap.
        CREATE_RECORD => {
            action.arguments.get("type").and_then(Value::as_str) == Some("Document")
                && action.arguments.get("kind").and_then(Value::as_str) == Some("handoff")
                && action
                    .arguments
                    .get("links")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|link| link.get("target_id").and_then(Value::as_str))
                    .any(|reference| {
                        let exact_touch_exists = action.touched.contains(reference);
                        eligible.iter().any(|id| {
                            action.touched.contains(id)
                                && if exact_touch_exists {
                                    reference == id
                                } else {
                                    record_reference_matches(reference, id)
                                }
                        })
                    })
        }
        _ => false,
    }
}

/// Match an original authored reference to a canonical successful touch. The
/// request boundary accepts exact ids or unique UUID prefixes; because this
/// call succeeded, a prefix matching an eligible touched id is the one the
/// handler resolved. This avoids re-resolving against mutable current state.
fn record_reference_matches(reference: &str, canonical_id: &str) -> bool {
    if reference == canonical_id {
        return true;
    }
    if !crate::mcp::record_ref::is_canonical_uuid_v4_or_v7(canonical_id) {
        return false;
    }
    let compact = reference
        .bytes()
        .filter(|byte| *byte != b'-')
        .map(|byte| byte.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if !(6..32).contains(&compact.len()) || !compact.iter().all(u8::is_ascii_hexdigit) {
        return false;
    }
    let canonical = canonical_id
        .bytes()
        .filter(|byte| *byte != b'-')
        .collect::<Vec<_>>();
    canonical.starts_with(&compact)
}

#[derive(Default)]
struct ObservedOverlapAction {
    tool: String,
    arguments: Value,
    touched: HashSet<String>,
    mutated: HashSet<String>,
}

#[cfg(test)]
mod overlap_coordination_tests {
    use super::*;

    const ELIGIBLE: &str = "01234567-89ab-4def-8abc-0123456789ab";

    fn handoff(arguments: Value) -> ObservedOverlapAction {
        ObservedOverlapAction {
            tool: "create_record".into(),
            arguments,
            touched: HashSet::from([ELIGIBLE.to_owned()]),
            mutated: HashSet::new(),
        }
    }

    #[test]
    fn handoff_requires_an_authored_link_to_the_eligible_canonical_touch() {
        let eligible = HashSet::from([ELIGIBLE.to_owned()]);
        assert!(!is_explicit_coordination(
            &handoff(json!({
                "type":"Document",
                "kind":"handoff",
                "home_id":"0123456"
            })),
            &eligible,
        ));
        assert!(!is_explicit_coordination(
            &handoff(json!({
                "type":"Document",
                "kind":"handoff",
                "home_id":"0123456",
                "links":[{"target_id":"abcdef0","relationship":"relates_to"}]
            })),
            &eligible,
        ));
        let mut exact_legacy_collision = handoff(json!({
            "type":"Document",
            "kind":"handoff",
            "home_id":"0123456",
            "links":[{"target_id":"0123456","relationship":"relates_to"}]
        }));
        exact_legacy_collision.touched.insert("0123456".to_owned());
        assert!(!is_explicit_coordination(
            &exact_legacy_collision,
            &eligible,
        ));
        assert!(is_explicit_coordination(
            &handoff(json!({
                "type":"Document",
                "kind":"handoff",
                "links":[{"target_id":"0123456","relationship":"relates_to"}]
            })),
            &eligible,
        ));
    }
}

async fn classify_overlap_claim(
    db: &Db,
    notice: &RetainedOverlapNotice,
    as_of: chrono::DateTime<chrono::Utc>,
) -> Result<(bool, Option<&'static str>)> {
    let completed_at = chrono::DateTime::parse_from_rfc3339(&notice.ended_at)
        .map_err(|_| Error::engine("get_run_activity: malformed overlap notice completion time"))?
        .with_timezone(&chrono::Utc);
    let deadline = completed_at + chrono::Duration::minutes(OVERLAP_OBSERVATION_MINUTES);
    let closed_at: Option<String> = match notice.run_key.as_deref() {
        Some(run_key) => {
            sqlx::query_scalar("SELECT ended_at FROM agent_runs WHERE run_key=? AND account_id=?")
                .bind(run_key)
                .bind(&notice.actor)
                .fetch_optional(db.pool())
                .await?
                .flatten()
        }
        None => None,
    };
    let closed_at = closed_at
        .as_deref()
        .map(chrono::DateTime::parse_from_rfc3339)
        .transpose()
        .map_err(|_| Error::engine("get_run_activity: malformed run closure time"))?
        .map(|time| time.with_timezone(&chrono::Utc))
        .filter(|time| *time >= completed_at);
    let boundary = closed_at.map_or(deadline, |closed| closed.min(deadline));
    if as_of < boundary {
        return Ok((false, None));
    }

    let Some(root_run) = notice.run_key.as_deref() else {
        return Ok((true, Some("no_observed_outcome")));
    };
    let rows = sqlx::query(
        "WITH RECURSIVE included_runs(run_key) AS (
             SELECT ?1
             UNION
             SELECT call.run_key
               FROM read_log_calls call
               JOIN included_runs parent ON call.parent_key=parent.run_key
              WHERE call.actor=?2 AND call.run_key IS NOT NULL
             UNION
             SELECT event.run_key
               FROM content_events event
               JOIN included_runs parent ON event.parent_key=parent.run_key
              WHERE event.actor=?2 AND event.run_key IS NOT NULL
         )
         SELECT call.seq,call.tool,call.arguments,dictionary.record_id,touch.interaction
           FROM read_log_calls call
           JOIN included_runs included ON included.run_key=call.run_key
           LEFT JOIN read_log_touches touch ON touch.call_seq=call.seq
           LEFT JOIN read_log_record_ids dictionary ON dictionary.record_ref=touch.record_ref
          WHERE call.actor=?2 AND call.outcome='ok' AND call.seq>?3
            AND call.ended_at>=?4 AND call.ended_at<=?5
          ORDER BY call.ended_at,call.seq,dictionary.record_id,touch.interaction",
    )
    .bind(root_run)
    .bind(&notice.actor)
    .bind(notice.seq)
    .bind(&notice.ended_at)
    .bind(boundary.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    .fetch_all(db.pool())
    .await?;

    let mut eligible = HashSet::new();
    let mut anchor_ids = HashSet::new();
    for anchor in &notice.emission.anchors {
        anchor_ids.insert(anchor.record_id.clone());
        eligible.insert(anchor.record_id.clone());
        eligible.extend(anchor.overlap_record_ids.iter().cloned());
    }
    let mut order = Vec::new();
    let mut actions: HashMap<i64, ObservedOverlapAction> = HashMap::new();
    for row in rows {
        let seq: i64 = row.try_get("seq")?;
        let action = actions.entry(seq).or_insert_with(|| {
            order.push(seq);
            let arguments = row
                .try_get::<String, _>("arguments")
                .ok()
                .and_then(|raw| serde_json::from_str(&raw).ok())
                .unwrap_or(Value::Null);
            ObservedOverlapAction {
                tool: row.try_get("tool").unwrap_or_default(),
                arguments,
                touched: HashSet::new(),
                mutated: HashSet::new(),
            }
        });
        if let Some(record_id) = row.try_get::<Option<String>, _>("record_id")? {
            action.touched.insert(record_id.clone());
            if row.try_get::<Option<String>, _>("interaction")?.as_deref() == Some("mutated") {
                action.mutated.insert(record_id);
            }
        }
    }

    for seq in order {
        let action = &actions[&seq];
        if action.tool == START_WORK
            && action.arguments.get("action").and_then(Value::as_str) == Some("release")
            && action.mutated.iter().any(|id| anchor_ids.contains(id))
        {
            return Ok((true, Some("released")));
        }
        if is_explicit_coordination(action, &eligible) {
            return Ok((true, Some("coordinated")));
        }
        if action_evidence::is_material_mutation_surface(&action.tool)
            && action.mutated.iter().any(|id| eligible.contains(id))
        {
            return Ok((true, Some("proceeded")));
        }
    }
    Ok((true, Some("no_observed_outcome")))
}

async fn work_overlap_evaluation(
    db: &Db,
    caller: &Caller,
    scope: OverlapEvaluationScope,
) -> Result<Value> {
    let as_of = crate::mcp::interactions::timestamp();
    if matches!(scope, OverlapEvaluationScope::Workspace) && !super::is_legacy_local(caller) {
        let admitted: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM member_contexts WHERE account_id=?)")
                .bind(caller.credential())
                .fetch_one(db.pool())
                .await?;
        if !admitted {
            return Err(Error::engine(
                "get_run_activity: workspace overlap evaluation requires a portable database member",
            ));
        }
    }

    let rows = match sqlx::query(
        "SELECT seq,id,run_key,actor,ended_at,result_annotation
           FROM read_log_calls
          WHERE outcome='ok' AND result_annotation IS NOT NULL AND ended_at<=?
          ORDER BY seq",
    )
    .bind(&as_of)
    .fetch_all(db.pool())
    .await
    {
        Ok(rows) => rows,
        Err(_) => {
            return Ok(overlap_evaluation_unavailable(
                &as_of,
                scope,
                "measurement_evidence_unavailable",
            ))
        }
    };

    let mut notices = Vec::new();
    let mut malformed_evidence = 0_i64;
    for row in rows {
        let actor: String = row.try_get("actor")?;
        if matches!(scope, OverlapEvaluationScope::Own) && actor != caller.credential() {
            continue;
        }
        let raw: String = row.try_get("result_annotation")?;
        let Ok(emission) = serde_json::from_str::<WorkOverlapEmission>(&raw) else {
            malformed_evidence += 1;
            continue;
        };
        if emission.kind != "work_overlap_emission"
            || emission.version != 1
            || !matches!(emission.surface.as_str(), "claim" | "create" | "set_intent")
            || emission.anchors.is_empty()
            || emission.anchors.iter().any(|anchor| {
                anchor.overlap_item_count < 1
                    || anchor.overlap_total_count < anchor.overlap_item_count
                    || usize::try_from(anchor.overlap_item_count).ok()
                        != Some(anchor.overlap_record_ids.len())
                    || anchor.truncated != (anchor.overlap_total_count > anchor.overlap_item_count)
            })
        {
            malformed_evidence += 1;
            continue;
        }
        notices.push(RetainedOverlapNotice {
            seq: row.try_get("seq")?,
            id: row.try_get("id")?,
            run_key: row.try_get("run_key")?,
            actor,
            ended_at: row.try_get("ended_at")?,
            emission,
        });
    }

    let as_of_time = chrono::DateTime::parse_from_rfc3339(&as_of)
        .expect("interaction timestamp is RFC3339")
        .with_timezone(&chrono::Utc);
    let mut by_surface =
        HashMap::from([("claim", 0_i64), ("create", 0_i64), ("set_intent", 0_i64)]);
    let mut anchor_count = 0_i64;
    let mut overlap_item_count = 0_i64;
    let mut overlap_disclosed_count = 0_i64;
    let mut outcomes = OverlapOutcomeCounts::default();
    let mut outcome_evidence_available = true;
    let mut observations = Vec::new();
    for notice in &notices {
        *by_surface
            .get_mut(notice.emission.surface.as_str())
            .expect("validated surface") += 1;
        anchor_count += i64::try_from(notice.emission.anchors.len()).unwrap_or(i64::MAX);
        overlap_item_count += notice
            .emission
            .anchors
            .iter()
            .map(|anchor| anchor.overlap_total_count)
            .sum::<i64>();
        overlap_disclosed_count += notice
            .emission
            .anchors
            .iter()
            .map(|anchor| anchor.overlap_item_count)
            .sum::<i64>();

        let (classification, classification_available) = if notice.emission.surface == "claim" {
            match classify_overlap_claim(db, notice, as_of_time).await {
                Ok((mature, outcome)) => {
                    if mature {
                        outcomes.mature += 1;
                        match outcome.expect("mature claims have an outcome") {
                            "released" => outcomes.released += 1,
                            "coordinated" => outcomes.coordinated += 1,
                            "proceeded" => outcomes.proceeded += 1,
                            "no_observed_outcome" => outcomes.no_observed_outcome += 1,
                            _ => unreachable!("classifier returns a closed outcome set"),
                        }
                    } else {
                        outcomes.pending += 1;
                    }
                    (outcome.map(str::to_string), true)
                }
                Err(_) => {
                    // The annotation remains valid emission evidence even if
                    // disposable follow-on call/touch/run evidence has been
                    // deleted or is unavailable. Never silently turn that
                    // absence into a behavioral zero.
                    outcome_evidence_available = false;
                    (None, false)
                }
            }
        } else {
            (None, true)
        };

        if matches!(scope, OverlapEvaluationScope::Own) {
            let mut visible_anchors = Vec::new();
            let mut visible_overlaps = Vec::new();
            let mut identifiers_withheld = false;
            for anchor in &notice.emission.anchors {
                if can_record_in_pool(db.pool(), caller, &anchor.record_id, Capability::View)
                    .await?
                {
                    visible_anchors.push(anchor.record_id.clone());
                } else {
                    identifiers_withheld = true;
                }
                for record_id in &anchor.overlap_record_ids {
                    if can_record_in_pool(db.pool(), caller, record_id, Capability::View).await? {
                        visible_overlaps.push(record_id.clone());
                    } else {
                        identifiers_withheld = true;
                    }
                }
            }
            visible_anchors.sort();
            visible_anchors.dedup();
            visible_overlaps.sort();
            visible_overlaps.dedup();
            observations.push(json!({
                "notice_id": notice.id,
                "surface": notice.emission.surface,
                "completed_at": notice.ended_at,
                "run_key": notice.run_key,
                "anchor_record_ids": visible_anchors,
                "overlap_record_ids": visible_overlaps,
                "anchor_count": notice.emission.anchors.len(),
                "overlap_item_count": notice.emission.anchors.iter().map(|anchor| anchor.overlap_total_count).sum::<i64>(),
                "disclosed_overlap_item_count": notice.emission.anchors.iter().map(|anchor| anchor.overlap_item_count).sum::<i64>(),
                "truncated": notice.emission.anchors.iter().any(|anchor| anchor.truncated),
                "identifiers_withheld": identifiers_withheld,
                "state": if notice.emission.surface != "claim" { "not_applicable" } else if !classification_available { "unavailable" } else if classification.is_some() { "mature" } else { "pending" },
                "outcome": classification,
            }));
        }
    }

    debug_assert_eq!(
        outcomes.mature,
        outcomes.released
            + outcomes.coordinated
            + outcomes.proceeded
            + outcomes.no_observed_outcome
    );
    let claim_outcomes = outcome_evidence_available.then(|| {
        json!({
            "unit": "mature_notice_bearing_claim_call",
            "mature_denominator": outcomes.mature,
            "pending_count": outcomes.pending,
            "released": outcomes.released,
            "coordinated": outcomes.coordinated,
            "proceeded": outcomes.proceeded,
            "no_observed_outcome": outcomes.no_observed_outcome,
        })
    });
    let mut result = json!({
        "view": "work_overlap_evaluation",
        "scope": match scope { OverlapEvaluationScope::Own => "own", OverlapEvaluationScope::Workspace => "workspace" },
        "as_of": as_of,
        "observation_window_seconds": OVERLAP_OBSERVATION_MINUTES * 60,
        "availability": {
            "status": "partial",
            "reason": if !outcome_evidence_available { "best_effort_retained_history_with_outcome_evidence_unavailable" } else if malformed_evidence == 0 { "best_effort_retained_history" } else { "best_effort_retained_history_with_malformed_evidence" },
            "complete_history": false,
            "retention": "The interaction log and its result annotations are disposable retained evidence. Counts cover retained, post-instrumentation annotations only; an empty result is not proof that no historical notice was emitted.",
            "malformed_evidence_count": malformed_evidence,
        },
        "emissions": {
            "unit": "notice_bearing_call",
            "notice_bearing_call_count": notices.len(),
            "by_surface": {
                "claim": by_surface["claim"],
                "create": by_surface["create"],
                "set_intent": by_surface["set_intent"],
            },
            "anchor_count": anchor_count,
            "overlap_item_count": overlap_item_count,
            "disclosed_overlap_item_count": overlap_disclosed_count,
        },
        "claim_outcomes": claim_outcomes,
    });
    if matches!(scope, OverlapEvaluationScope::Own) {
        result
            .as_object_mut()
            .expect("evaluation is an object")
            .insert("observations".into(), Value::Array(observations));
    }
    Ok(result)
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
             SELECT activity_id,run_key,started_at,start_event_id,
                    CASE WHEN ended_at IS NOT NULL AND ended_at<=? THEN ended_at END AS observed_ended_at,
                    CASE WHEN ended_at IS NULL OR ended_at>? THEN 0 ELSE 1 END AS open_rank,
                    CASE WHEN ended_at IS NULL OR ended_at>? THEN started_at ELSE ended_at END AS sort_at
               FROM agent_runs
              WHERE account_id=? AND started_at<=?
                AND (ended_at IS NULL OR ended_at>?)
         )
         SELECT candidates.activity_id,candidates.run_key,candidates.started_at,
                candidates.observed_ended_at,candidates.open_rank,candidates.sort_at,
                start_event.payload AS start_payload
           FROM candidates
           JOIN control_events start_event ON start_event.id=candidates.start_event_id
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
    .fetch_all(db.pool())
    .await?;
    let has_more = rows.len() as i64 > limit;
    let page = rows.iter().take(limit as usize);
    let mut runs = Vec::with_capacity(rows.len().min(limit as usize));
    for row in page {
        let run_key: String = row.try_get("run_key")?;
        let started_at: String = row.try_get("started_at")?;
        let start_payload: String = row.try_get("start_payload")?;
        let admission_channel =
            serde_json::from_str::<crate::control::AgentRunStartedPayload>(&start_payload)
                .ok()
                .and_then(|start| start.channel)
                .unwrap_or(Channel::Unknown);
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
            "channel": {
                "kind": admission_channel.as_str(),
                "assurance": if admission_channel == Channel::Unknown { "unknown_or_withheld" } else { "server_observed" },
            },
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
    .fetch_optional(db.pool())
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
    .fetch_one(db.pool())
    .await?;
    let transient = sqlx::query_scalar::<_, Option<String>>(
        "SELECT MAX(ended_at) FROM read_log_calls
          WHERE run_key=? AND actor=? AND outcome='ok' AND ended_at<=?",
    )
    .bind(run_key)
    .bind(caller.credential())
    .bind(observed_at)
    .fetch_one(db.pool())
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

pub(crate) async fn record_versions_at(
    db: &Db,
    caller: &Caller,
    record_id: &str,
    before_seq: i64,
    after_seq: i64,
) -> Result<(Value, Value)> {
    if before_seq < 1 || after_seq < before_seq {
        return Err(Error::engine("get_record_version seq must be positive"));
    }
    let before_resolved = lens::resolve_as_of(
        db,
        AsOfSelector::ContentSeq(ContentSeqSelector {
            content_seq: before_seq,
        }),
    )
    .await?;
    let after_resolved = lens::resolve_as_of(
        db,
        AsOfSelector::ContentSeq(ContentSeqSelector {
            content_seq: after_seq,
        }),
    )
    .await?;
    let events = events::log_prefix(db, after_resolved.resolved_content_seq).await?;
    let split = events.partition_point(|event| event.local_seq <= before_seq);

    let scratch = open_database(":memory:").await?;
    let result: Result<(Value, Value)> = async {
        apply_schema(&scratch).await?;
        lens::replay_projection_events(&scratch, &events[..split]).await?;
        let before = read_record_version(db, &scratch, caller, record_id, &before_resolved).await?;
        lens::replay_projection_events(&scratch, &events[split..]).await?;
        let after = read_record_version(db, &scratch, caller, record_id, &after_resolved).await?;
        Ok((before, after))
    }
    .await;
    scratch.close().await;
    result
}

async fn read_record_version(
    live: &Db,
    scratch: &Db,
    caller: &Caller,
    record_id: &str,
    resolved: &lens::ResolvedAsOf,
) -> Result<Value> {
    let read_lens = ReadLens::historical(scratch, live, resolved);
    let record = read::get_record_with_lens_as(
        &read_lens,
        record_id,
        read::EnrichOptions::default(),
        super::principal(caller),
    )
    .await?;
    match record {
        Some(mut record) => {
            super::lifecycle::filter_enriched_record_with_auth(
                scratch,
                live,
                caller,
                &mut record,
                read::EnrichOptions::default(),
            )
            .await?;
            Ok(json!({ "as_of_seq": resolved.resolved_content_seq, "record": record }))
        }
        None => Err(Error::engine(format!(
            "record {} has no state as of seq {}",
            record_id, resolved.resolved_content_seq
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
        "Authorization-filtered window over the content event log; first page pins high water, next_request round-trips verbatim. Groups split on (record, actor, run, channel, executor) with channel {kind, assurance} and executor {kind, assurance}; unknown when unattested or invalidated.",

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
        "With for_run, aggregate read activity for that run and optional descendants; no intent or raw trace data. Without for_run, page the caller account's open or recent durable runs with keys, retained-intent status, and best-effort freshness. Other accounts are excluded. Pass overlap_evaluation instead to measure retained privacy-safe overlap-notice emissions: own returns the originating account's notice detail, while workspace returns aggregate counts only. Missing or deleted evidence is explicitly unavailable or partial, never interpreted as a historical zero.",
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
                },
                "overlap_evaluation": {
                    "type": "object",
                    "properties": {
                        "scope": {
                            "type": "string",
                            "enum": ["own", "workspace"],
                            "description": "own returns notice-level detail only for the authenticated account; workspace returns aggregate counts only."
                        }
                    },
                    "required": ["scope"],
                    "additionalProperties": false,
                    "description": "Evaluate retained work-overlap notice emissions and mature claim outcomes. Mutually exclusive with ordinary run-activity arguments."
                }
            },
            "additionalProperties": false
        }),
        get_run_activity,
    )?;
    Ok(())
}

#[cfg(test)]
mod run_activity_batch_tests {
    use super::*;
    use crate::authorization::{replace_explicit_policy, AllowEntry};
    use crate::db::{
        create_database, with_read_pool_acquisition_counter, with_write_pool_acquisition_counter,
    };

    const RUN: &str = "heron-river-c748b2";
    const CHILD: &str = "scout-chair-a748b2";

    async fn calls(db: &Db, run: &str, parent: Option<&str>, actor: &str, count: usize) {
        let mut tx = db.write_pool().begin().await.unwrap();
        let head: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM read_log_calls")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        sqlx::query(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?)
             INSERT INTO read_log_calls(id,tool,run_key,parent_key,actor,outcome,started_at,ended_at)
             SELECT printf('fixture-%d',i+?), 'search', ?, ?, ?, 'ok',
                    '2026-09-17T00:00:00Z','2026-09-17T00:00:00Z' FROM n",
        ).bind(count as i64).bind(head).bind(run).bind(parent).bind(actor)
            .execute(&mut *tx).await.unwrap();
        // Each call both surfaces and opens every dictionary record. The
        // aggregate counts interactions, not unique records, after visibility.
        sqlx::query(
            "INSERT INTO read_log_touches(call_seq,record_ref,interaction)
             SELECT c.seq,d.record_ref,k.interaction FROM read_log_calls c
             CROSS JOIN read_log_record_ids d
             CROSS JOIN (SELECT 'surfaced' AS interaction UNION ALL SELECT 'opened') k
             WHERE c.seq>?",
        )
        .bind(head)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    /// Handler-body read-pool acquisitions for one `get_run_activity` call.
    /// The endpoint is non-mutating and now reads exclusively through the
    /// physically read-only pool, so its write-pool count is measured
    /// separately by [`measure_write`].
    async fn measure(db: &Db, children: bool) -> (Value, u64) {
        let (result, acquisitions) = with_read_pool_acquisition_counter(get_run_activity(
            db.clone(),
            Caller::authenticated("acct:viewer"),
            json!({"for_run":RUN,"include_child_runs":children}),
        ))
        .await;
        (result.unwrap(), acquisitions)
    }

    async fn measure_write(db: &Db, children: bool) -> u64 {
        let (result, acquisitions) = with_write_pool_acquisition_counter(get_run_activity(
            db.clone(),
            Caller::authenticated("acct:viewer"),
            json!({"for_run":RUN,"include_child_runs":children}),
        ))
        .await;
        result.unwrap();
        acquisitions
    }

    #[tokio::test]
    async fn run_activity_visibility_cost_is_independent_of_repeated_touches() {
        let db = create_database(":memory:").await.unwrap();
        let visible = crate::store::create_record(
            &db,
            json!({"type":"Document","kind":"note","name":"Visible target"}),
        )
        .await
        .unwrap();
        let hidden = crate::store::create_record(
            &db,
            json!({"type":"Document","kind":"note","name":"Hidden target"}),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            &visible,
            vec![AllowEntry::account("acct:viewer", Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(&db, "test:policy", &hidden, vec![])
            .await
            .unwrap();
        for id in [visible.as_str(), hidden.as_str(), "missing-record"] {
            sqlx::query("INSERT INTO read_log_record_ids(record_id) VALUES(?)")
                .bind(id)
                .execute(db.write_pool())
                .await
                .unwrap();
        }
        calls(&db, RUN, None, "acct:viewer", 10).await;
        // Measure the former per-touch visibility loop independently of the
        // endpoint's fixed ownership/log reads. This is a positive control
        // for the acquisition counter and a conservative before reference.
        let (_, scalar_cost) = with_write_pool_acquisition_counter(async {
            let caller = Caller::authenticated("acct:viewer");
            for _ in 0..20 {
                for (id, expected) in [
                    (visible.as_str(), true),
                    (hidden.as_str(), false),
                    ("missing-record", false),
                ] {
                    assert_eq!(
                        can_record(&db, &caller, id, Capability::View)
                            .await
                            .unwrap(),
                        expected
                    );
                }
            }
        })
        .await;
        assert!(
            scalar_cost >= 60,
            "scalar control observed only {scalar_cost} acquisitions"
        );
        let (small, small_cost) = measure(&db, false).await;
        assert_eq!(small["read_activity"][0]["searches"], 10);
        assert_eq!(small["read_activity"][0]["surfaced"], 10);
        assert_eq!(small["read_activity"][0]["opened"], 10);
        assert_eq!(small["availability"]["visibility_filtered"], true);
        // The endpoint is non-mutating and now runs entirely on the physically
        // read-only pool: no handler-body read may take a writer slot.
        assert_eq!(
            measure_write(&db, false).await,
            0,
            "get_run_activity took a write-pool connection"
        );

        calls(&db, RUN, None, "acct:viewer", 200).await;
        calls(&db, CHILD, Some(RUN), "acct:viewer", 3).await;
        // Matching run keys are correlation, not authority to read another
        // principal's calls. These must not contribute to any count.
        calls(&db, RUN, None, "acct:other", 7).await;
        let (large, large_cost) = measure(&db, false).await;
        assert_eq!(large["read_activity"].as_array().unwrap().len(), 1);
        assert_eq!(large["read_activity"][0]["searches"], 210);
        assert_eq!(large["read_activity"][0]["surfaced"], 210);
        assert_eq!(large["read_activity"][0]["opened"], 210);
        assert_eq!(
            small_cost, large_cost,
            "repeated touches added pool acquisitions"
        );
        assert!(
            large_cost >= 1,
            "get_run_activity took no read-pool connections: {large_cost}"
        );
        eprintln!("run activity: scalar visibility for 60 touches {scalar_cost} write-pool acquisitions; full endpoint at 60 -> 1260 touches {small_cost} -> {large_cost} read-pool acquisitions");

        let (tree, tree_cost) = measure(&db, true).await;
        assert_eq!(tree["read_activity"].as_array().unwrap().len(), 2);
        assert_eq!(tree["read_activity"][1]["run_key"], CHILD);
        assert_eq!(tree["read_activity"][1]["parent_key"], RUN);
        assert_eq!(tree["read_activity"][1]["opened"], 3);
        assert_eq!(tree_cost, large_cost);

        // No cache survives a request: revocation removes touch counts on the
        // next poll, while the caller's own historical search count remains.
        replace_explicit_policy(&db, "test:policy", &visible, vec![])
            .await
            .unwrap();
        let (revoked, _) = measure(&db, false).await;
        assert_eq!(revoked["read_activity"][0]["searches"], 210);
        assert_eq!(revoked["read_activity"][0]["surfaced"], 0);
        assert_eq!(revoked["read_activity"][0]["opened"], 0);
        assert_eq!(revoked["availability"]["visibility_filtered"], true);
        db.close().await;
    }

    /// `get_history` must never hold two read-pool connections at once.
    ///
    /// The handler opens one read snapshot for the whole page walk, and the
    /// database-identity read also acquires a read-pool connection. If that
    /// identity read ran while the snapshot was held, a pool with only one
    /// free slot would stall: hold all but one of the read pool's five
    /// connections and a nested checkout has nothing to take. The identity
    /// memo is cold here (`create_database` seeds the row but not the memo),
    /// so this is a genuine detector, not a warm-cache no-op.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_history_never_holds_two_read_pool_connections() {
        let db = create_database(":memory:").await.unwrap();
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(db.pool().acquire().await.unwrap());
        }
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            get_history(db.clone(), Caller::authenticated("acct:viewer"), json!({})),
        )
        .await
        .expect("get_history nested a second read-pool connection")
        .unwrap();
        assert!(output.get("events").is_some());
        drop(held);
        db.close().await;
    }
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
