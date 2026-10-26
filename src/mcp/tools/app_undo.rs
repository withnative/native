//! Undo everything one app did since a point in time — engine preview and
//! apply, increment 1 (task `650d870`, plan `182cd53`).
//!
//! Decision `48e1ff9` makes undo the safety net for apps that act as the
//! user. The app's writes are selected engine-side by package through
//! [`app_action_outputs_on`](crate::mcp::app_attribution::app_action_outputs_on),
//! scoped to the caller's own account, and kept when they were written at or
//! after `since`.
//!
//! Each selected event is mapped to the *aspects* it touched: a record's
//! existence, a field, the body, a facet key (including `archived`) or a
//! link. A plain link is a `link.added`/`link.removed` content event; most
//! everyday links (`relates_to`, `depends_on`) are relationship-owned and
//! live as support/contest assertions on a `legacy_link.v1` relationship,
//! reverted through the same compatibility route `manage_links` uses. For each aspect the base is its value just before the app's
//! first write to it in the window. The plan item then says:
//!
//! - `unchanged`: it already holds the base (so a re-run writes nothing);
//! - `conflict`: someone other than the app wrote that aspect afterwards, so
//!   nothing is written over their edit;
//! - `unavailable`: the caller can no longer act on the record;
//! - `unsupported`: increment 1 has no inverse for it (deletes, messages,
//!   non-link relationships, moves, observation-only facets);
//! - `revert`: the inverse write is planned (`reverted` once applied).
//!
//! Apply recomputes the plan inside one write transaction, never trusting a
//! preview, and commits every inverse write or none. It runs under its own
//! provenance dispatch for [`OPERATION`], so the commit issues one action
//! attestation covering every inverse event, content and relationship
//! alike. Each content event also carries an `undo` marker naming the
//! package and the app events it reverses; a relationship assertion carries
//! the operation in its rationale.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use serde::Serialize;
use serde_json::{json, Map, Value};
use sqlx::{Row, Sqlite, Transaction};

use crate::authorization::Capability;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::mcp::registry::Caller;
use crate::store::{append_in, AppendSpec};

/// The provenance operation an apply is attested under.
pub const OPERATION: &str = "undo_app_writes";

/// How an undo's relationship assertion names the package it reverted, after
/// the compatibility rationale.
const UNDO_PACKAGE_NOTE: &str = "; package=";

/// Record fields increment 1 restores. Moves, ownership, kind and
/// persistence changes are reported `unsupported`.
const REVERTIBLE_FIELDS: [&str; 4] = ["name", "summary", "maturity", "lifecycle"];
const UNSUPPORTED_FIELDS: [&str; 4] = ["home_id", "owner_id", "kind", "persistence"];

/// Event types that do not change what a record says (mirrors the exclusion
/// list of `idx_content_events_record_changes`).
const NON_CHANGE_TYPES: [&str; 4] = [
    "occurrence.bound.v1",
    "receipt.dependency_audited.v1",
    "reconciliation.recorded.v1",
    "unit.superseded.v1",
];

/// Body previews in plan items stop here; the full body is still restored.
const BODY_PREVIEW_CHARS: usize = 120;

/// What to undo: one package's writes for the caller's account since `since`
/// (RFC 3339), optionally only one version's.
#[derive(Clone, Debug)]
pub struct AppUndoRequest {
    pub package: String,
    pub since: String,
    pub version: Option<String>,
    /// Stored on every inverse event, like any other write's reason.
    pub reason: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UndoStatus {
    Revert,
    Reverted,
    Unchanged,
    Conflict,
    Unsupported,
    Unavailable,
}

/// The later write that blocks a revert.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UndoConflict {
    pub event_id: String,
    pub actor: Option<String>,
    pub at: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct UndoItem {
    pub record_id: String,
    /// `record`, `existence`, `field:<name>`, `body`, `facet:<key>`, or
    /// `link:<relationship>:<target id>`; `relationship` for relationship
    /// outputs, whose `record_id` is the relationship id.
    pub aspect: String,
    pub status: UndoStatus,
    /// The inverse write: `archive`, `set`, `unset`, `add_link` or
    /// `remove_link`. Present for `revert`/`reverted` items.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<&'static str>,
    /// Why an item is not reverted, as a short code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Value>,
    /// The app's own events this item reverses.
    pub reverses: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conflict: Option<UndoConflict>,
    /// A sentence for the person, where the reason code alone is not enough.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Events the apply wrote for this item.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub written: Vec<String>,
}

impl UndoItem {
    fn new(record_id: &str, aspect: String, status: UndoStatus) -> Self {
        Self {
            record_id: record_id.to_string(),
            aspect,
            status,
            action: None,
            reason: None,
            from: None,
            to: None,
            reverses: Vec::new(),
            conflict: None,
            detail: None,
            written: Vec::new(),
        }
    }

    fn because(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AppUndoOutcome {
    pub package: String,
    pub since: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub applied: bool,
    pub items: Vec<UndoItem>,
    /// The attestation(s) covering the inverse events; empty for a preview
    /// or an apply that wrote nothing.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub action_attestation_ids: Vec<String>,
}

impl AppUndoOutcome {
    pub fn count(&self, status: UndoStatus) -> usize {
        self.items
            .iter()
            .filter(|item| item.status == status)
            .count()
    }
}

/// Read-only: what an apply would do now.
pub async fn preview_app_undo(
    db: &Db,
    caller: &Caller,
    request: &AppUndoRequest,
) -> Result<AppUndoOutcome> {
    let since = validate(caller, request)?;
    let mut tx = db.pool().begin().await?;
    let planned = plan_in(db, &mut tx, caller, request, &since).await?;
    tx.rollback().await?;
    Ok(outcome(request, &since, false, planned, Vec::new()))
}

/// Revert every revertible item in one transaction, attested as one action.
pub async fn apply_app_undo(
    db: &Db,
    caller: &Caller,
    request: &AppUndoRequest,
) -> Result<AppUndoOutcome> {
    let since = validate(caller, request)?;
    let arguments = json!({
        "package": request.package,
        "since": since,
        "version": request.version,
        "reason": request.reason,
    });
    let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
        caller,
        OPERATION,
        &arguments,
        caller.intent(),
    );
    let annotations = crate::store::EventAnnotations {
        run_key: caller.run_key().map(String::from),
        parent_key: caller.parent_key().map(String::from),
        intent: caller.intent().map(String::from),
    };
    let planned = dispatch
        .scope(crate::store::with_event_annotations(
            annotations,
            apply_in(db, caller, request, &since),
        ))
        .await?;
    Ok(outcome(
        request,
        &since,
        true,
        planned,
        dispatch.receipt_ids(),
    ))
}

fn validate(caller: &Caller, request: &AppUndoRequest) -> Result<String> {
    // Undo stays a human act, like installing: an app cannot undo apps
    // (its undo would also be attributed to it and re-selected next time).
    if caller.host_asserted_app().is_some() {
        return Err(Error::engine(format!(
            "{OPERATION} is not available to apps (app_operation_refused)"
        )));
    }
    if request.package.trim().is_empty() {
        return Err(Error::engine(format!("{OPERATION}: package is required")));
    }
    if request.reason.trim().is_empty() {
        return Err(Error::engine(format!("{OPERATION}: reason is required")));
    }
    let since = chrono::DateTime::parse_from_rfc3339(request.since.trim())
        .map_err(|_| Error::engine(format!("{OPERATION}: since must be an RFC 3339 timestamp")))?;
    Ok(since
        .with_timezone(&chrono::Utc)
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

fn outcome(
    request: &AppUndoRequest,
    since: &str,
    applied: bool,
    planned: Vec<Planned>,
    action_attestation_ids: Vec<String>,
) -> AppUndoOutcome {
    AppUndoOutcome {
        package: request.package.clone(),
        since: since.to_string(),
        version: request.version.clone(),
        applied,
        items: planned.into_iter().map(|planned| planned.item).collect(),
        action_attestation_ids,
    }
}

async fn apply_in(
    db: &Db,
    caller: &Caller,
    request: &AppUndoRequest,
    since: &str,
) -> Result<Vec<Planned>> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut planned = plan_in(db, &mut tx, caller, request, since).await?;
    let touched: Vec<String> = planned
        .iter()
        .filter(|planned| planned.write.is_some())
        .map(|planned| planned.item.record_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if touched.is_empty() {
        tx.rollback().await?;
        return Ok(planned);
    }
    let touched_refs: Vec<&str> = touched.iter().map(String::as_str).collect();
    let schema_rows = crate::query::cascade::schema_config_rows_in(&mut tx).await?;
    let before =
        super::lifecycle::required_violations_in(&mut tx, &schema_rows, &touched_refs).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    // Relationship assertions name their authoring attestation, so one
    // identity is reserved up front and finalised over every output below.
    let draft = crate::provenance::reserve_action_attestation()?;
    for entry in &mut planned {
        let Some(write) = entry.write.take() else {
            continue;
        };
        if let InverseWrite::RelationshipLink {
            target_id,
            relationship,
            add,
        } = &write
        {
            let package_note = format!("package={}", request.package);
            let (_, outputs) =
                crate::relationship::legacy::mutate_with_reserved_attestation_noted_in(
                    &mut tx,
                    caller,
                    &entry.item.record_id,
                    target_id,
                    relationship,
                    None,
                    *add,
                    OPERATION,
                    Some(&package_note),
                    &draft,
                    &mut act_alloc,
                )
                .await?;
            entry
                .item
                .written
                .extend(outputs.into_iter().map(|output| output.event_id));
            entry.item.status = UndoStatus::Reverted;
            continue;
        }
        let marker = json!({
            "package": request.package,
            "since": since,
            "reverses": entry.item.reverses,
        });
        for spec in write.specs(&entry.item.record_id, caller.actor()) {
            let mut spec = spec;
            if let Some(payload) = spec.payload.as_object_mut() {
                payload.insert("reason".into(), json!(request.reason));
                payload.insert("undo".into(), marker.clone());
            }
            let event = append_in(db, &mut tx, spec, &mut act_alloc).await?;
            entry.item.written.push(event.id);
        }
        entry.item.status = UndoStatus::Reverted;
    }
    let after =
        super::lifecycle::required_violations_in(&mut tx, &schema_rows, &touched_refs).await?;
    crate::domain_transaction::assert_required_not_worsened(OPERATION, &before, &after)?;
    crate::provenance::issue_reserved_pending_action_in(&mut tx, draft).await?;
    db.commit_content(tx).await?;
    Ok(planned)
}

/// One plan item and, for `revert`, the inverse write.
struct Planned {
    item: UndoItem,
    write: Option<InverseWrite>,
}

impl Planned {
    fn report(item: UndoItem) -> Self {
        Self { item, write: None }
    }
}

enum InverseWrite {
    Archive,
    Field {
        key: String,
        value: Value,
    },
    Body(String),
    FacetSet(Map<String, Value>),
    FacetUnset(String),
    LinkAdd {
        target_id: String,
        relationship: String,
        note: Option<String>,
    },
    LinkRemove {
        target_id: String,
        relationship: String,
    },
    /// Support (`add`) or contest a relationship-owned link.
    RelationshipLink {
        target_id: String,
        relationship: String,
        add: bool,
    },
}

impl InverseWrite {
    fn action(&self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Field { .. } | Self::Body(_) | Self::FacetSet(_) => "set",
            Self::FacetUnset(_) => "unset",
            Self::LinkAdd { .. } | Self::RelationshipLink { add: true, .. } => "add_link",
            Self::LinkRemove { .. } | Self::RelationshipLink { add: false, .. } => "remove_link",
        }
    }

    /// Content events for this write; a relationship-owned link has none
    /// (see [`apply_in`]).
    fn specs(self, record_id: &str, actor: &str) -> Vec<AppendSpec> {
        let spec = |event_type: &str, payload: Value| AppendSpec {
            record_id: record_id.to_string(),
            event_type: event_type.into(),
            payload,
            actor: Some(actor.to_string()),
        };
        match self {
            Self::Archive => vec![spec(
                "facet.set",
                json!({"key": crate::schema::ARCHIVED_FACET_KEY, "value": "true"}),
            )],
            Self::Field { key, value } => vec![spec("record.updated", json!({ key: value }))],
            Self::Body(body) => vec![spec("record.updated", json!({ "body": body }))],
            Self::FacetSet(payload) => vec![spec("facet.set", Value::Object(payload))],
            Self::FacetUnset(key) => vec![spec("facet.unset", json!({ "key": key }))],
            Self::LinkAdd {
                target_id,
                relationship,
                note,
            } => {
                let mut payload = json!({
                    "source_id": record_id,
                    "target_id": target_id,
                    "relationship": relationship,
                });
                if let Some(note) = note {
                    payload["note"] = json!(note);
                }
                vec![spec("link.added", payload)]
            }
            Self::LinkRemove {
                target_id,
                relationship,
            } => vec![spec(
                "link.removed",
                json!({
                    "source_id": record_id,
                    "target_id": target_id,
                    "relationship": relationship,
                }),
            )],
            Self::RelationshipLink { .. } => Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Aspect {
    Field(String),
    Body,
    Facet(String),
    Link {
        target_id: String,
        relationship: String,
    },
}

impl Aspect {
    fn label(&self) -> String {
        match self {
            Self::Field(key) => format!("field:{key}"),
            Self::Body => "body".into(),
            Self::Facet(key) => format!("facet:{key}"),
            Self::Link {
                target_id,
                relationship,
            } => format!("link:{relationship}:{target_id}"),
        }
    }

    fn capability(&self) -> Capability {
        match self {
            Self::Facet(key) if key == crate::schema::ARCHIVED_FACET_KEY => Capability::Manage,
            _ => Capability::Edit,
        }
    }

    /// Whether `event` (on this aspect's record) wrote this aspect.
    fn touched_by(&self, event: &Event) -> bool {
        let payload = &event.payload;
        match self {
            Self::Field(key) => match event.event_type.as_str() {
                "record.created" | "record.updated" => field_value(payload, key).is_some(),
                // Spine facets project into the same record columns.
                "facet.set" | "facet.unset" => {
                    is_current_facet_write(payload)
                        && payload.get("key").and_then(Value::as_str) == Some(key)
                }
                _ => false,
            },
            Self::Body => match event.event_type.as_str() {
                "record.created" | "unit.revision.recorded.v1" | "message.revision.recorded.v1" => {
                    true
                }
                "record.updated" | "receipt.committed.v1" => payload.get("body").is_some(),
                _ => false,
            },
            Self::Facet(key) => {
                matches!(event.event_type.as_str(), "facet.set" | "facet.unset")
                    && is_current_facet_write(payload)
                    && payload.get("key").and_then(Value::as_str) == Some(key)
            }
            Self::Link {
                target_id,
                relationship,
            } => {
                matches!(event.event_type.as_str(), "link.added" | "link.removed")
                    && payload.get("target_id").and_then(Value::as_str) == Some(target_id)
                    && payload.get("relationship").and_then(Value::as_str) == Some(relationship)
            }
        }
    }
}

/// Whether a facet event changes the current value. Only observation-only
/// events leave it alone: a back-dated `facet.set` without the flag keeps
/// its current-plus-observation semantics and still moves the value.
fn is_current_facet_write(payload: &Value) -> bool {
    !payload
        .get("observation_only")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Spine facets that are also revertible record fields.
const SPINE_FIELD_FACETS: [&str; 2] = ["lifecycle", "maturity"];
/// Spine facets increment 1 does not revert.
const SPINE_UNSUPPORTED_FACETS: [&str; 2] = ["owner", "persistence"];

/// A field's value in a `record.created`/`record.updated` payload, top level
/// or under `fields`. An explicit null is a value.
fn field_value<'a>(payload: &'a Value, key: &str) -> Option<&'a Value> {
    payload
        .get(key)
        .or_else(|| payload.get("fields").and_then(|fields| fields.get(key)))
}

struct Event {
    seq: i64,
    id: String,
    event_type: String,
    payload: Value,
    actor: Option<String>,
    created_at: String,
}

impl Event {
    fn from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Self> {
        let raw: Option<String> = row.try_get("payload")?;
        Ok(Self {
            seq: row.try_get("seq")?,
            id: row.try_get("id")?,
            event_type: row.try_get("type")?,
            payload: raw
                .as_deref()
                .map(serde_json::from_str)
                .transpose()?
                .unwrap_or(Value::Null),
            actor: row.try_get("actor")?,
            created_at: row.try_get("created_at")?,
        })
    }

    /// The package an undo event's marker names.
    fn undo_package(&self) -> Option<&str> {
        self.payload
            .get("undo")
            .and_then(|undo| undo.get("package"))
            .and_then(Value::as_str)
    }

    /// The `since` an undo event's marker names.
    fn undo_since(&self) -> Option<&str> {
        self.payload
            .get("undo")
            .and_then(|undo| undo.get("since"))
            .and_then(Value::as_str)
    }

    fn conflict(&self) -> UndoConflict {
        UndoConflict {
            event_id: self.id.clone(),
            actor: self.actor.clone(),
            at: self.created_at.clone(),
        }
    }
}

/// Everything the planner needs about the app's writes.
struct Selection {
    /// Every content event of the selected app (any time), so a later write
    /// by the app itself is never mistaken for someone else's.
    app_ids: HashSet<String>,
    /// The same for relationship events.
    app_relationship_ids: HashSet<String>,
    /// Outputs of the caller's own earlier undos (non-invalidated
    /// attestations under [`OPERATION`] for this principal). An undo needs
    /// both this membership and a marker naming the package: the marker
    /// scopes it to a package, and membership means no other write that
    /// copies the marker can pose as one.
    undo_ids: HashSet<String>,
    package: String,
    /// The request's normalised `since`.
    since: String,
}

impl Selection {
    /// An earlier undo of this package by the caller: part of the app's
    /// chain, never "someone else".
    fn is_undo(&self, event: &Event) -> bool {
        self.undo_ids.contains(&event.id) && event.undo_package() == Some(self.package.as_str())
    }

    /// A later write that is neither the app's nor an earlier undo of it.
    fn is_foreign(&self, event: &Event) -> bool {
        !self.app_ids.contains(&event.id) && !self.is_undo(event)
    }

    /// The relationship counterpart of [`Self::is_undo`]: the caller's own
    /// undo assertion, whose rationale names this package.
    fn is_relationship_undo(&self, event: &RelationshipEvent) -> bool {
        self.undo_ids.contains(&event.id) && event.undo_package() == Some(self.package.as_str())
    }

    fn is_foreign_relationship(&self, event: &RelationshipEvent) -> bool {
        !self.app_relationship_ids.contains(&event.id) && !self.is_relationship_undo(event)
    }
}

async fn plan_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    request: &AppUndoRequest,
    since: &str,
) -> Result<Vec<Planned>> {
    let outputs = crate::mcp::app_attribution::app_action_outputs_on(
        tx,
        caller.credential(),
        &request.package,
    )
    .await?;
    let ids_in = |domain: &str| -> HashSet<String> {
        outputs
            .iter()
            .filter(|output| output.output_domain == domain)
            .map(|output| output.output_event_id.clone())
            .collect()
    };
    let undo_ids: Vec<String> = sqlx::query_scalar(
        "SELECT o.output_event_id
           FROM provenance_action_outputs AS o
           JOIN provenance_action_attestations AS a ON a.id = o.action_attestation_id
          WHERE a.operation = ? AND a.principal = ?
            AND NOT EXISTS (
                  SELECT 1 FROM provenance_attestation_validity_events AS v
                   WHERE v.attestation_id = a.id
                     AND v.status = 'invalidated'
                     AND v.ordinal = (SELECT MAX(v2.ordinal)
                                        FROM provenance_attestation_validity_events AS v2
                                       WHERE v2.attestation_id = v.attestation_id))",
    )
    .bind(OPERATION)
    .bind(caller.credential().trim())
    .fetch_all(&mut **tx)
    .await?;
    // Every version's writes are the app's own; a version filter narrows only
    // what is reverted, so another version's write is never a "conflict".
    let selection = Selection {
        app_ids: ids_in("content"),
        app_relationship_ids: ids_in("relationship"),
        undo_ids: undo_ids.into_iter().collect(),
        package: request.package.clone(),
        since: since.to_string(),
    };
    let targets = |domain: &str| -> Vec<&str> {
        outputs
            .iter()
            .filter(|output| {
                output.output_domain == domain
                    && request
                        .version
                        .as_deref()
                        .is_none_or(|version| output.version == version)
            })
            .map(|output| output.output_event_id.as_str())
            .collect()
    };
    let content_ids = targets("content");
    let relationship_ids = targets("relationship");

    let rows = sqlx::query(
        "SELECT seq, id, record_id, type, payload, actor, created_at
           FROM content_events
          WHERE id IN (SELECT value FROM json_each(?1))
            AND julianday(created_at) >= julianday(?2)
          ORDER BY seq",
    )
    .bind(serde_json::to_string(&content_ids)?)
    .bind(since)
    .fetch_all(&mut **tx)
    .await?;
    let mut by_record: BTreeMap<i64, (String, Vec<Event>)> = BTreeMap::new();
    let mut first_seq_of: BTreeMap<String, i64> = BTreeMap::new();
    for row in &rows {
        let record_id: String = row.try_get("record_id")?;
        let event = Event::from_row(row)?;
        let first = *first_seq_of.entry(record_id.clone()).or_insert(event.seq);
        by_record
            .entry(first)
            .or_insert_with(|| (record_id, Vec::new()))
            .1
            .push(event);
    }

    let mut planned = Vec::new();
    for (record_id, events) in by_record.into_values() {
        plan_record_in(
            db,
            tx,
            caller,
            &selection,
            &record_id,
            &events,
            &mut planned,
        )
        .await?;
    }

    if !relationship_ids.is_empty() {
        plan_relationships_in(
            tx,
            caller,
            &selection,
            &relationship_ids,
            since,
            &mut planned,
        )
        .await?;
    }
    Ok(planned)
}

/// Plan one record's items from the app's in-window events on it.
async fn plan_record_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    selection: &Selection,
    record_id: &str,
    events: &[Event],
    planned: &mut Vec<Planned>,
) -> Result<()> {
    let reverses = |events: &[&Event]| events.iter().map(|event| event.id.clone()).collect();
    let row = sqlx::query(
        "SELECT type, deleted_at, name, summary, maturity, lifecycle, body
           FROM records WHERE id = ?",
    )
    .bind(record_id)
    .fetch_optional(&mut **tx)
    .await?;
    let all: Vec<&Event> = events.iter().collect();
    let Some(row) = row else {
        let mut item =
            UndoItem::new(record_id, "record".into(), UndoStatus::Unsupported).because("missing");
        item.reverses = reverses(&all);
        planned.push(Planned::report(item));
        return Ok(());
    };
    // A tombstone is frozen and has no undelete yet. Saying so discloses
    // nothing beyond the id of a record the caller's own app wrote.
    if row.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        let mut item =
            UndoItem::new(record_id, "record".into(), UndoStatus::Unsupported).because("deleted");
        item.reverses = reverses(&all);
        planned.push(Planned::report(item));
        return Ok(());
    }
    // Nothing about a record the caller can no longer see is disclosed.
    if !super::can_record_in(tx, caller, record_id, Capability::View).await? {
        planned.push(Planned::report(UndoItem::new(
            record_id,
            "record".into(),
            UndoStatus::Unavailable,
        )));
        return Ok(());
    }
    let record_type: String = row.try_get("type")?;

    if let Some(created) = events.iter().find(|e| e.event_type == "record.created") {
        let mut item = UndoItem::new(record_id, "existence".into(), UndoStatus::Revert);
        item.reverses = reverses(&all);
        if record_type == "Message" {
            item.status = UndoStatus::Unsupported;
            planned.push(Planned::report(item.because("message_send")));
            return Ok(());
        }
        if !super::can_record_in(tx, caller, record_id, Capability::Manage).await? {
            item.status = UndoStatus::Unavailable;
            planned.push(Planned::report(item));
            return Ok(());
        }
        let archived =
            super::lifecycle::facet_state_in(tx, record_id, crate::schema::ARCHIVED_FACET_KEY)
                .await?
                .is_some();
        if archived {
            item.status = UndoStatus::Unchanged;
            planned.push(Planned::report(item));
            return Ok(());
        }
        let later = events_after_in(tx, record_id, created.seq).await?;
        if let Some(foreign) = later.iter().rev().find(|event| {
            !NON_CHANGE_TYPES.contains(&event.event_type.as_str()) && selection.is_foreign(event)
        }) {
            item.status = UndoStatus::Conflict;
            item.conflict = Some(foreign.conflict());
            planned.push(Planned::report(item.because("edited_since")));
            return Ok(());
        }
        if has_live_members_in(tx, record_id).await? {
            item.status = UndoStatus::Conflict;
            planned.push(Planned::report(item.because("has_members")));
            return Ok(());
        }
        item.action = Some("archive");
        item.from = Some(json!("live"));
        item.to = Some(json!("archived"));
        planned.push(Planned {
            item,
            write: Some(InverseWrite::Archive),
        });
        return Ok(());
    }

    // Map each event to the aspects it wrote, or report it unsupported.
    let mut aspects: BTreeMap<Aspect, Vec<&Event>> = BTreeMap::new();
    let mut unsupported: BTreeMap<String, Vec<&Event>> = BTreeMap::new();
    for event in events {
        match event.event_type.as_str() {
            "record.updated" => {
                for key in REVERTIBLE_FIELDS {
                    if field_value(&event.payload, key).is_some() {
                        aspects
                            .entry(Aspect::Field(key.into()))
                            .or_default()
                            .push(event);
                    }
                }
                for key in UNSUPPORTED_FIELDS {
                    if field_value(&event.payload, key).is_some() {
                        unsupported
                            .entry(format!("field:{key}"))
                            .or_default()
                            .push(event);
                    }
                }
                if event.payload.get("body").is_some() {
                    aspects.entry(Aspect::Body).or_default().push(event);
                }
            }
            "facet.set" | "facet.unset" => {
                let Some(key) = event.payload.get("key").and_then(Value::as_str) else {
                    unsupported
                        .entry(event.event_type.clone())
                        .or_default()
                        .push(event);
                    continue;
                };
                if SPINE_FIELD_FACETS.contains(&key) && is_current_facet_write(&event.payload) {
                    aspects
                        .entry(Aspect::Field(key.into()))
                        .or_default()
                        .push(event);
                } else if SPINE_UNSUPPORTED_FACETS.contains(&key) {
                    unsupported
                        .entry(format!("field:{key}"))
                        .or_default()
                        .push(event);
                } else if !is_current_facet_write(&event.payload) {
                    unsupported
                        .entry(format!("facet:{key}"))
                        .or_default()
                        .push(event);
                } else {
                    aspects
                        .entry(Aspect::Facet(key.into()))
                        .or_default()
                        .push(event);
                }
            }
            "link.added" | "link.removed" => {
                let target = event.payload.get("target_id").and_then(Value::as_str);
                let relationship = event.payload.get("relationship").and_then(Value::as_str);
                match (target, relationship) {
                    (Some(target_id), Some(relationship)) => aspects
                        .entry(Aspect::Link {
                            target_id: target_id.into(),
                            relationship: relationship.into(),
                        })
                        .or_default()
                        .push(event),
                    _ => unsupported
                        .entry(event.event_type.clone())
                        .or_default()
                        .push(event),
                }
            }
            other => unsupported
                .entry(other.to_string())
                .or_default()
                .push(event),
        }
    }
    for (label, events) in unsupported {
        let mut item = UndoItem::new(record_id, label.clone(), UndoStatus::Unsupported);
        item.reason = Some(match label.as_str() {
            "record.deleted" => "delete".into(),
            label if label.starts_with("message.") => "message_send".into(),
            label if label.starts_with("facet:") => "facet_observation".into(),
            label if label.starts_with("field:") => "field_not_revertible".into(),
            label => label.to_string(),
        });
        item.reverses = reverses(&events);
        planned.push(Planned::report(item));
    }
    if aspects.is_empty() {
        return Ok(());
    }
    let first = aspects
        .values()
        .filter_map(|events| events.first().map(|event| event.seq))
        .min()
        .expect("aspects are non-empty");
    let later = events_after_in(tx, record_id, first).await?;
    for (aspect, events) in aspects {
        let first_seq = events[0].seq;
        let mut item = UndoItem::new(record_id, aspect.label(), UndoStatus::Revert);
        item.reverses = reverses(&events);
        if !super::can_record_in(tx, caller, record_id, aspect.capability()).await? {
            item.status = UndoStatus::Unavailable;
            planned.push(Planned::report(item));
            continue;
        }
        let touching: Vec<&Event> = later
            .iter()
            .filter(|event| event.seq > first_seq && aspect.touched_by(event))
            .collect();
        // The last write to this aspect is an earlier undo of this package
        // over the same window: already reverted, whatever normalisation the
        // projection applied. An undo from a later `since` restored a later
        // base, so it does not count.
        if touching.last().is_some_and(|event| {
            selection.is_undo(event) && event.undo_since() == Some(selection.since.as_str())
        }) {
            item.status = UndoStatus::Unchanged;
            planned.push(Planned::report(item));
            continue;
        }
        let Some((current, base, write)) =
            resolve_in(tx, &row, record_id, &aspect, first_seq).await?
        else {
            item.status = UndoStatus::Unsupported;
            planned.push(Planned::report(item.because("not_revertible")));
            continue;
        };
        item.from = Some(display(&aspect, &current));
        item.to = Some(display(&aspect, &base));
        if current == base {
            item.status = UndoStatus::Unchanged;
            planned.push(Planned::report(item));
            continue;
        }
        // A foreign write the app itself later overwrote is already gone;
        // only one after the app's last write here would be lost.
        let last_app_seq = events.last().map_or(first_seq, |event| event.seq);
        if let Some(foreign) = touching
            .iter()
            .rev()
            .filter(|event| event.seq > last_app_seq)
            .find(|event| selection.is_foreign(event))
        {
            item.status = UndoStatus::Conflict;
            item.conflict = Some(foreign.conflict());
            planned.push(Planned::report(item.because("edited_since")));
            continue;
        }
        let hold = match aspect {
            Aspect::Body => crate::coedit::live::session_holds_body(db, record_id),
            _ => None,
        };
        if let Some(hold) = hold {
            use crate::coedit::live::BodyHold;
            let (reason, detail) = match hold {
                BodyHold::Editing => (
                    "live_session",
                    "someone is editing this live; try again once they have closed it",
                ),
                BodyHold::Saving => (
                    "live_edit_saving",
                    "a live edit is being saved; try again in a moment",
                ),
            };
            item.status = UndoStatus::Conflict;
            item.detail = Some(detail.into());
            planned.push(Planned::report(item.because(reason)));
            continue;
        }
        if matches!(&write, InverseWrite::FacetSet(payload)
            if payload.get("key").and_then(Value::as_str) == Some(crate::schema::ARCHIVED_FACET_KEY))
            && has_live_members_in(tx, record_id).await?
        {
            item.status = UndoStatus::Conflict;
            planned.push(Planned::report(item.because("has_members")));
            continue;
        }
        if let Some(reason) = link_blocker_in(tx, caller, record_id, &aspect).await? {
            item.status = UndoStatus::Unsupported;
            planned.push(Planned::report(item.because(reason)));
            continue;
        }
        item.action = Some(write.action());
        planned.push(Planned {
            item,
            write: Some(write),
        });
    }
    Ok(())
}

/// One relationship event of the app's.
struct RelationshipEvent {
    seq: i64,
    id: String,
    event_type: String,
    payload: Value,
    actor: String,
    occurred_at: String,
}

impl RelationshipEvent {
    fn stance(&self) -> Option<&str> {
        self.payload.get("stance").and_then(Value::as_str)
    }

    /// The package an undo assertion's rationale names
    /// (`"... ; package=<package>"`; a package never contains `;`).
    fn undo_package(&self) -> Option<&str> {
        self.payload
            .get("rationale")
            .and_then(Value::as_str)
            .and_then(|rationale| rationale.rsplit_once(UNDO_PACKAGE_NOTE))
            .map(|(_, package)| package)
    }
}

/// Plan the app's relationship outputs. Relationship-owned links revert to
/// the stance before the app's first assertion; anything else is listed as
/// unsupported in increment 1.
async fn plan_relationships_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    selection: &Selection,
    relationship_ids: &[&str],
    since: &str,
    planned: &mut Vec<Planned>,
) -> Result<()> {
    let origin: String =
        sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
            .fetch_one(&mut **tx)
            .await?;
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT e.relationship_id, r.type_definition_id, r.relationship_type
           FROM relationship_events e
           JOIN relationships r
             ON r.relationship_origin_db_id = e.relationship_origin_db_id
            AND r.relationship_id = e.relationship_id
          WHERE e.id IN (SELECT value FROM json_each(?1))
            AND e.relationship_origin_db_id = ?2
            AND julianday(e.occurred_at) >= julianday(?3)
          GROUP BY e.relationship_id
          ORDER BY MIN(e.seq)",
    )
    .bind(serde_json::to_string(relationship_ids)?)
    .bind(&origin)
    .bind(since)
    .fetch_all(&mut **tx)
    .await?;
    for (relationship_id, definition, token) in rows {
        let events = relationship_events_in(tx, &origin, &relationship_id).await?;
        let app_events: Vec<&RelationshipEvent> = events
            .iter()
            .filter(|event| {
                selection.app_relationship_ids.contains(&event.id)
                    && chrono::DateTime::parse_from_rfc3339(&event.occurred_at)
                        .ok()
                        .zip(chrono::DateTime::parse_from_rfc3339(since).ok())
                        .is_some_and(|(at, since)| at >= since)
            })
            .collect();
        let reverses: Vec<String> = app_events.iter().map(|event| event.id.clone()).collect();
        let endpoints: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT role, record_id FROM relationship_endpoints
              WHERE relationship_origin_db_id = ? AND relationship_id = ?",
        )
        .bind(&origin)
        .bind(&relationship_id)
        .fetch_all(&mut **tx)
        .await?;
        let endpoint = |role: &str| {
            endpoints
                .iter()
                .find(|(r, _)| r == role)
                .and_then(|(_, id)| id.clone())
        };
        let (Some(source_id), Some(target_id)) = (endpoint("source"), endpoint("target")) else {
            let mut item = UndoItem::new(
                &relationship_id,
                "relationship".into(),
                UndoStatus::Unsupported,
            )
            .because("relationship");
            item.reverses = reverses;
            planned.push(Planned::report(item));
            continue;
        };
        // Nothing about a link whose ends the caller can no longer see.
        if !super::can_record_in(tx, caller, &source_id, Capability::View).await?
            || !super::can_record_in(tx, caller, &target_id, Capability::View).await?
        {
            planned.push(Planned::report(UndoItem::new(
                &source_id,
                "record".into(),
                UndoStatus::Unavailable,
            )));
            continue;
        }
        let assertions: Vec<&RelationshipEvent> = app_events
            .iter()
            .copied()
            .filter(|event| event.event_type == "assertion.created.v1")
            .collect();
        let other_kinds = app_events.iter().any(|event| {
            !matches!(
                event.event_type.as_str(),
                "assertion.created.v1" | "relationship.created.v1"
            )
        });
        let mut item = UndoItem::new(
            &source_id,
            format!("link:{token}:{target_id}"),
            UndoStatus::Revert,
        );
        item.reverses = reverses;
        if definition != crate::relationship::legacy::LEGACY_LINK_DEFINITION_ID
            || assertions.is_empty()
            || other_kinds
        {
            item.aspect = "relationship".into();
            item.status = UndoStatus::Unsupported;
            planned.push(Planned::report(item.because("relationship")));
            continue;
        }
        let (live, status): (bool, Option<String>) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM records WHERE id = ?1 AND deleted_at IS NULL),
                    (SELECT status FROM relationships
                      WHERE relationship_origin_db_id = ?2 AND relationship_id = ?3)",
        )
        .bind(&source_id)
        .bind(&origin)
        .bind(&relationship_id)
        .fetch_one(&mut **tx)
        .await?;
        if !live {
            item.status = UndoStatus::Unsupported;
            planned.push(Planned::report(item.because("deleted")));
            continue;
        }
        if !super::can_record_in(tx, caller, &source_id, Capability::Edit).await? {
            item.status = UndoStatus::Unavailable;
            planned.push(Planned::report(item));
            continue;
        }
        if status.as_deref() != Some("active") {
            item.status = UndoStatus::Unsupported;
            planned.push(Planned::report(item.because("relationship_retired")));
            continue;
        }
        let first_seq = assertions[0].seq;
        let last_app_seq = app_events.last().map_or(first_seq, |event| event.seq);
        // The stance before the app's first assertion. A heuristic for the
        // effective state then: retractions and several claimants are not
        // folded in increment 1.
        // TODO(650d870, increment 2): fold assertion retractions and
        // invalidations, and every claimant's stance, into the base, e.g. by
        // replaying the legacy-link reducer over events before `first_seq`.
        // Pinned by `a_retracted_support_before_the_app_is_a_known_base_gap`.
        let base_linked = events
            .iter()
            .rev()
            .filter(|event| event.seq < first_seq && event.event_type == "assertion.created.v1")
            .find_map(RelationshipEvent::stance)
            == Some("support");
        let current_linked = sqlx::query_scalar::<_, Option<String>>(
            "SELECT effective_state FROM effective_relationships
              WHERE relationship_origin_db_id = ? AND relationship_id = ?",
        )
        .bind(&origin)
        .bind(&relationship_id)
        .fetch_optional(&mut **tx)
        .await?
        .flatten()
        .as_deref()
            == Some("active");
        let present = |linked: bool| json!(if linked { "linked" } else { "unlinked" });
        item.from = Some(present(current_linked));
        item.to = Some(present(base_linked));
        // Every later event counts, not only assertions: a retraction or an
        // invalidation by someone else is an edit too.
        let later: Vec<&RelationshipEvent> = events
            .iter()
            .filter(|event| event.seq > first_seq)
            .collect();
        if current_linked == base_linked {
            item.status = UndoStatus::Unchanged;
            planned.push(Planned::report(item));
            continue;
        }
        if let Some(foreign) = later
            .iter()
            .rev()
            .filter(|event| event.seq > last_app_seq)
            .find(|event| selection.is_foreign_relationship(event))
        {
            item.status = UndoStatus::Conflict;
            item.conflict = Some(UndoConflict {
                event_id: foreign.id.clone(),
                actor: Some(foreign.actor.clone()),
                at: foreign.occurred_at.clone(),
            });
            planned.push(Planned::report(item.because("edited_since")));
            continue;
        }
        let write = InverseWrite::RelationshipLink {
            target_id,
            relationship: token,
            add: base_linked,
        };
        item.action = Some(write.action());
        planned.push(Planned {
            item,
            write: Some(write),
        });
    }
    Ok(())
}

/// Every event of one local relationship, in order.
async fn relationship_events_in(
    tx: &mut Transaction<'static, Sqlite>,
    origin: &str,
    relationship_id: &str,
) -> Result<Vec<RelationshipEvent>> {
    let rows: Vec<(i64, String, String, String, String, String)> = sqlx::query_as(
        "SELECT seq, id, type, payload, actor, occurred_at FROM relationship_events
          WHERE relationship_origin_db_id = ? AND relationship_id = ?
          ORDER BY seq",
    )
    .bind(origin)
    .bind(relationship_id)
    .fetch_all(&mut **tx)
    .await?;
    rows.into_iter()
        .map(|(seq, id, event_type, payload, actor, occurred_at)| {
            Ok(RelationshipEvent {
                seq,
                id,
                event_type,
                payload: serde_json::from_str(&payload)?,
                actor,
                occurred_at,
            })
        })
        .collect()
}

/// The engine refuses to archive a folder that still homes live members
/// (archived members count), so undo reports it instead of failing.
async fn has_live_members_in(
    tx: &mut Transaction<'static, Sqlite>,
    record_id: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM records WHERE home_id = ? AND deleted_at IS NULL)",
    )
    .bind(record_id)
    .fetch_one(&mut **tx)
    .await?)
}

/// Every event on the record after `seq`, in order.
async fn events_after_in(
    tx: &mut Transaction<'static, Sqlite>,
    record_id: &str,
    seq: i64,
) -> Result<Vec<Event>> {
    let rows = sqlx::query(
        "SELECT seq, id, record_id, type, payload, actor, created_at
           FROM content_events WHERE record_id = ? AND seq > ? ORDER BY seq",
    )
    .bind(record_id)
    .bind(seq)
    .fetch_all(&mut **tx)
    .await?;
    rows.iter().map(Event::from_row).collect()
}

/// `(current, base, inverse)` for one aspect, as comparable values. `None`
/// when the aspect has no inverse here.
async fn resolve_in(
    tx: &mut Transaction<'static, Sqlite>,
    row: &sqlx::sqlite::SqliteRow,
    record_id: &str,
    aspect: &Aspect,
    first_seq: i64,
) -> Result<Option<(Value, Value, InverseWrite)>> {
    match aspect {
        Aspect::Field(key) => {
            let current: Option<String> = row.try_get(key.as_str())?;
            let mut base = Value::Null;
            let payloads: Vec<(String, String)> = sqlx::query_as(
                "SELECT type, payload FROM content_events
                  WHERE record_id = ? AND seq < ?
                    AND type IN ('record.created', 'record.updated', 'facet.set', 'facet.unset')
                  ORDER BY seq DESC",
            )
            .bind(record_id)
            .bind(first_seq)
            .fetch_all(&mut **tx)
            .await?;
            for (event_type, payload) in payloads {
                let payload: Value = serde_json::from_str(&payload)?;
                if event_type.starts_with("facet.") {
                    if SPINE_FIELD_FACETS.contains(&key.as_str())
                        && is_current_facet_write(&payload)
                        && payload.get("key").and_then(Value::as_str) == Some(key)
                    {
                        base = payload.get("value").cloned().unwrap_or(Value::Null);
                        break;
                    }
                    continue;
                }
                if let Some(value) = field_value(&payload, key) {
                    base = value.clone();
                    break;
                }
            }
            let mut current = current.map_or(Value::Null, Value::String);
            // A name is never null; an absent name reads as empty.
            if key == "name" {
                for value in [&mut current, &mut base] {
                    if value.is_null() {
                        *value = json!("");
                    }
                }
            }
            if !(base.is_null() || base.is_string()) {
                return Ok(None);
            }
            let write = InverseWrite::Field {
                key: key.clone(),
                value: base.clone(),
            };
            Ok(Some((current, base, write)))
        }
        Aspect::Body => {
            let current: Option<String> = row.try_get("body")?;
            let base = crate::record_body::body_at_seq_in(tx, record_id, first_seq - 1)
                .await?
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .unwrap_or_default();
            Ok(Some((
                json!(current.unwrap_or_default()),
                json!(base),
                InverseWrite::Body(base),
            )))
        }
        Aspect::Facet(key) => {
            let current = super::lifecycle::facet_state_in(tx, record_id, key)
                .await?
                .map(|(value, vocab_ref)| json!({"value": value, "vocab_ref": vocab_ref}))
                .unwrap_or(Value::Null);
            let payloads: Vec<String> = sqlx::query_scalar(
                "SELECT payload FROM content_events
                  WHERE record_id = ? AND seq < ?
                    AND type IN ('facet.set', 'facet.unset')
                    AND json_extract(payload, '$.key') = ?
                  ORDER BY seq DESC",
            )
            .bind(record_id)
            .bind(first_seq)
            .bind(key)
            .fetch_all(&mut **tx)
            .await?;
            for raw in payloads {
                let payload: Value = serde_json::from_str(&raw)?;
                if !is_current_facet_write(&payload) {
                    continue;
                }
                let Some(value) = payload.get("value").filter(|v| !v.is_null()) else {
                    // An unset (or a set with no value) leaves it absent.
                    return Ok(Some((
                        current,
                        Value::Null,
                        InverseWrite::FacetUnset(key.clone()),
                    )));
                };
                let vocab_ref = payload.get("vocab_ref").cloned().unwrap_or(Value::Null);
                let mut restored = Map::new();
                restored.insert("key".into(), json!(key));
                restored.insert("value".into(), value.clone());
                if !vocab_ref.is_null() {
                    restored.insert("vocab_ref".into(), vocab_ref.clone());
                }
                if let Some(kind) = payload.get(crate::events::FACET_TIME_KIND_MEMBER) {
                    restored.insert(crate::events::FACET_TIME_KIND_MEMBER.into(), kind.clone());
                }
                let base = json!({"value": value, "vocab_ref": vocab_ref});
                return Ok(Some((current, base, InverseWrite::FacetSet(restored))));
            }
            Ok(Some((
                current,
                Value::Null,
                InverseWrite::FacetUnset(key.clone()),
            )))
        }
        Aspect::Link {
            target_id,
            relationship,
        } => {
            let current: Option<Option<String>> = sqlx::query_scalar(
                "SELECT note FROM links
                  WHERE source_id = ? AND target_id = ? AND relationship = ?",
            )
            .bind(record_id)
            .bind(target_id)
            .bind(relationship)
            .fetch_optional(&mut **tx)
            .await?;
            let previous: Option<(String, String)> = sqlx::query_as(
                "SELECT type, payload FROM content_events
                  WHERE record_id = ? AND seq < ?
                    AND type IN ('link.added', 'link.removed')
                    AND json_extract(payload, '$.target_id') = ?
                    AND json_extract(payload, '$.relationship') = ?
                  ORDER BY seq DESC LIMIT 1",
            )
            .bind(record_id)
            .bind(first_seq)
            .bind(target_id)
            .bind(relationship)
            .fetch_optional(&mut **tx)
            .await?;
            let base_note = match previous {
                Some((event_type, payload)) if event_type == "link.added" => {
                    let payload: Value = serde_json::from_str(&payload)?;
                    Some(
                        payload
                            .get("note")
                            .and_then(Value::as_str)
                            .map(String::from),
                    )
                }
                _ => None,
            };
            // A link is compared by presence and note: the app re-adding an
            // existing link with another note is a change too. Re-adding with
            // the base note restores it (`link.added` upserts the note).
            let state = |link: &Option<Option<String>>| match link {
                Some(note) => json!({"linked": true, "note": note}),
                None => json!("unlinked"),
            };
            let write = match &base_note {
                Some(note) => InverseWrite::LinkAdd {
                    target_id: target_id.clone(),
                    relationship: relationship.clone(),
                    note: note.clone(),
                },
                None => InverseWrite::LinkRemove {
                    target_id: target_id.clone(),
                    relationship: relationship.clone(),
                },
            };
            Ok(Some((state(&current), state(&base_note), write)))
        }
    }
}

/// Link reverts also need View on the target, a plain (not
/// relationship-owned) link, and a mutable bearer. Returns why not.
async fn link_blocker_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    record_id: &str,
    aspect: &Aspect,
) -> Result<Option<&'static str>> {
    let Aspect::Link {
        target_id,
        relationship,
    } = aspect
    else {
        return Ok(None);
    };
    if !super::can_record_in(tx, caller, target_id, Capability::View).await? {
        return Ok(Some("target_unavailable"));
    }
    if super::links::relationship_owned_in(tx, record_id, target_id, relationship).await? {
        return Ok(Some("relationship"));
    }
    if crate::comments::assert_bearer_immutable_on(tx, OPERATION, record_id, relationship)
        .await
        .is_err()
    {
        return Ok(Some("immutable_link"));
    }
    Ok(None)
}

/// What a plan item shows: bodies are shortened, everything else as is.
fn display(aspect: &Aspect, value: &Value) -> Value {
    match (aspect, value) {
        (Aspect::Body, Value::String(body)) if body.chars().count() > BODY_PREVIEW_CHARS => {
            let mut short: String = body.chars().take(BODY_PREVIEW_CHARS).collect();
            short.push('…');
            json!(short)
        }
        _ => value.clone(),
    }
}
