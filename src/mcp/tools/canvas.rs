//! Native Canvas v1 tools — `read_canvas` (scene, changes) and `manage_canvas`
//! (commit_batch).
//!
//! The protocol lives in [`crate::canvas`]; this module owns authorization,
//! compare-and-set, idempotent replay, disclosure and the structured result
//! envelope. Every outcome a client must show — committed, replayed, conflict,
//! rejected — is a 200 result, never an engine error, so an agent or the
//! workbench can render it without parsing error text.
//!
//! Disclosure rule (`redact_for`): a record id appears in a canvas response
//! only if the caller holds View on that record at read time; otherwise it is
//! replaced by the literal `"withheld"` and nothing else about the record is
//! emitted. Geometry is visible to anyone with View on the canvas.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::Deserialize;
use serde_json::{json, Map, Value};
use sqlx::{Row, Sqlite, SqliteConnection, Transaction};

use crate::authorization::Capability;
use crate::canvas::{
    self, BatchEnvelope, CanvasVersion, Detached, Expected, FoldError, ObjectKind, Op, PatchSet,
    PreImage, Refusal, SceneObject, StoredBatch, BATCH_VERSION, CANVAS_BATCH_EVENT_TYPE,
    CHANGES_VERSION, PROMOTE_VERSION, RESULT_VERSION, SCENE_VERSION, WITHHELD,
};
use crate::db::Db;
use crate::error::{Error, Result};
use crate::query::lens;
use crate::store::{append_in, AppendSpec};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{can_record, can_record_in, parse_args, require_record_in, visible_ids_preloaded_in};

const READ_TOOL: &str = "read_canvas";
const WRITE_TOOL: &str = "manage_canvas";
const DEFAULT_CHANGES_LIMIT: usize = 200;
const MAX_CHANGES_LIMIT: usize = 200;

/// At most this many objects in one promotion plan. Deliberately far below the
/// batch op limit: a promotion mints records, and a plan a person is expected
/// to review should stay reviewable.
const MAX_PROMOTE_ITEMS: usize = 50;

/// One object to turn into a record.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PromoteItem {
    object_id: String,
    #[serde(rename = "type")]
    record_type: String,
    kind: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    facets: Option<Map<String, Value>>,
    #[serde(default)]
    home_id: Option<String>,
}

/// One link to write once the records exist. An endpoint naming a promoted
/// object resolves to that object's new record; anything else is read as a
/// record id that already exists.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PromoteLink {
    from: String,
    to: String,
    relationship: String,
    #[serde(default)]
    note: Option<String>,
}

/// What the plan was made against.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PromoteExpected {
    canvas_version: String,
    #[serde(default)]
    objects: BTreeMap<String, Expected>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ReadCanvasArgs {
    GetScene {
        canvas_id: String,
        #[serde(default)]
        include_deleted: bool,
    },
    Changes {
        canvas_id: String,
        after: String,
        limit: Option<usize>,
    },
    Describe {
        canvas_id: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ManageCanvasArgs {
    CommitBatch {
        batch: Value,
    },
    AssertConnector {
        canvas_id: String,
        object_id: String,
        relationship: String,
        #[serde(default)]
        note: Option<String>,
        #[serde(default)]
        expected: Option<Expected>,
    },
    Promote {
        canvas_id: String,
        items: Vec<PromoteItem>,
        #[serde(default)]
        links: Vec<PromoteLink>,
        #[serde(default)]
        dry_run: bool,
        #[serde(default)]
        expected: Option<PromoteExpected>,
        #[serde(default)]
        plan_digest: Option<String>,
        reason: String,
    },
}

// ---- disclosure ----------------------------------------------------------

fn record_id_of_card(props: &Map<String, Value>) -> Option<&str> {
    props.get("record_id").and_then(Value::as_str)
}

/// Every record id a scene object or op could disclose.
fn referenced_record_ids(objects: &[Value], ops: &[Op]) -> Vec<String> {
    let mut ids = BTreeSet::new();
    for object in objects {
        if object.get("kind").and_then(Value::as_str) == Some("record_card") {
            if let Some(id) = object.pointer("/props/record_id").and_then(Value::as_str) {
                ids.insert(id.to_owned());
            }
        }
    }
    for op in ops {
        if let Op::Create { object } = op {
            if object.kind == ObjectKind::RecordCard {
                if let Some(id) = record_id_of_card(&object.props) {
                    ids.insert(id.to_owned());
                }
            }
        }
    }
    ids.into_iter().collect()
}

/// The authorized face of a visible record card's record. A summary, not the
/// full projection: `get_record` remains the way to open it.
async fn record_face(conn: &mut SqliteConnection, record_id: &str) -> Result<Option<Value>> {
    let row = sqlx::query(
        "SELECT r.id,r.type,r.kind,r.name,r.summary,r.maturity,
                EXISTS (SELECT 1 FROM facet_values av
                         WHERE av.record_id = r.id AND av.key = ?) AS archived,
                (SELECT MAX(seq) FROM content_events WHERE record_id=r.id) AS head
           FROM records r WHERE r.id=? AND r.deleted_at IS NULL",
    )
    .bind(crate::schema::ARCHIVED_FACET_KEY)
    .bind(record_id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let head: Option<i64> = row.try_get("head")?;
    Ok(Some(json!({
        "id": row.try_get::<String, _>("id")?,
        "type": row.try_get::<String, _>("type")?,
        "kind": row.try_get::<Option<String>, _>("kind")?,
        "name": row.try_get::<String, _>("name")?,
        "summary": row.try_get::<Option<String>, _>("summary")?,
        "archived": row.try_get::<i64, _>("archived")? != 0,
        "maturity": row.try_get::<Option<String>, _>("maturity")?,
        "version": head.map(|seq| format!("rec:{seq}")),
    })))
}

/// Withhold every record reference the caller may not see. `faces` supplies
/// the resolved record summary for visible cards; withheld cards keep their
/// geometry and lose everything else.
fn redact_object(object: &mut Value, visible: &HashSet<String>, faces: &HashMap<String, Value>) {
    if object.get("kind").and_then(Value::as_str) != Some("record_card") {
        return;
    }
    let Some(props) = object.get_mut("props").and_then(Value::as_object_mut) else {
        return;
    };
    let record_id = props
        .get("record_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    match record_id {
        Some(id) if visible.contains(&id) => {
            let face = faces.get(&id).cloned().unwrap_or(Value::Null);
            object["record"] = face;
        }
        _ => {
            props.insert("record_id".into(), Value::String(WITHHELD.into()));
            props.remove("promoted_from");
        }
    }
}

/// Resolve every asserted connector's `semantic` for one caller.
///
/// Two things happen here, and both are disclosure rules rather than
/// cosmetics:
///
/// * `link_id` is shown only when the caller holds View on **both** endpoint
///   records. A content-owned id spells `lnk:{source}:{target}:{relationship}`
///   and therefore leaks both record ids to anyone who can read it.
/// * `broken` is derived, never stored: an asserted connector whose link row
///   has since been removed reads `broken`. It is derived only when both
///   endpoints are visible, because "there is no longer a link between those
///   two records" is itself a fact about records the caller may not see.
async fn resolve_connector_semantics(
    conn: &mut SqliteConnection,
    values: &mut [Value],
    cards: &HashMap<String, String>,
    visible: &HashSet<String>,
) -> Result<()> {
    for object in values.iter_mut() {
        if object.get("kind").and_then(Value::as_str) != Some("connector") {
            continue;
        }
        let endpoints: Vec<Option<String>> = ["from", "to"]
            .iter()
            .map(|end| {
                object
                    .get("props")
                    .and_then(|props| props.get(*end))
                    .and_then(Value::as_object)
                    .and_then(|endpoint| endpoint.get("object"))
                    .and_then(Value::as_str)
                    .and_then(|anchor| cards.get(anchor).cloned())
            })
            .collect();
        let both_visible = endpoints
            .iter()
            .all(|record| record.as_deref().is_some_and(|id| visible.contains(id)));
        let Some(semantic) = object
            .get_mut("props")
            .and_then(|props| props.get_mut("semantic"))
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        if !both_visible {
            // The whole assertion is withheld, not just its id. "A `blocks`
            // link exists between the records these two cards name" is a fact
            // about those records, and `relationship` and `status` carry it
            // just as surely as `link_id` does. Replacing the object with the
            // literal follows the same rule every other withheld reference on
            // a canvas obeys: emit nothing else about it.
            *object
                .get_mut("props")
                .and_then(|props| props.get_mut("semantic"))
                .expect("the semantic object was just borrowed") = Value::String(WITHHELD.into());
            continue;
        }
        let asserted = semantic.get("status").and_then(Value::as_str) == Some("asserted");
        let relationship = semantic
            .get("relationship")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if !asserted || relationship.is_empty() {
            continue;
        }
        let (Some(source), Some(target)) = (endpoints[0].clone(), endpoints[1].clone()) else {
            continue;
        };
        let live: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM links WHERE source_id=? AND target_id=? AND relationship=?)",
        )
        .bind(&source)
        .bind(&target)
        .bind(&relationship)
        .fetch_one(&mut *conn)
        .await?;
        if !live {
            semantic.insert("status".into(), Value::String("broken".into()));
        }
    }
    Ok(())
}

fn withhold_record_reference(props: &mut Map<String, Value>, visible: &HashSet<String>) {
    let visible_record = props
        .get("record_id")
        .and_then(Value::as_str)
        .is_some_and(|id| visible.contains(id));
    if !visible_record {
        if props.contains_key("record_id") {
            props.insert("record_id".into(), Value::String(WITHHELD.into()));
        }
        props.remove("promoted_from");
    }
    // A connector's `semantic` is withheld whole and unconditionally on the
    // change feed. `link_id` names both endpoint records outright, and
    // `relationship` with `status` carry the same fact in another form; an op
    // does not carry enough context to resolve its endpoints and check View
    // on each the way get_scene can, so the feed cannot make that judgement
    // and does not try. The scene is where a caller who may see both ends
    // learns the assertion; withholding it here costs nothing else, because
    // a client cannot author `semantic` in the first place (PropsAuthority).
    if props.get("semantic").is_some_and(Value::is_object) {
        props.insert("semantic".into(), Value::String(WITHHELD.into()));
    }
}

fn redact_op(op: &Op, visible: &HashSet<String>) -> Value {
    let mut value = serde_json::to_value(op).expect("ops serialize");
    let pointer = match op {
        // Every create, not just a record card: an engine-authored batch may
        // create a connector carrying `semantic`, and redacting by kind here
        // would contradict the by-shape rule the next arm relies on.
        Op::Create { .. } => "/object/props",
        // A patch never legitimately carries a record id (the fold refuses
        // it), but the feed redacts by shape, not by trust in the writer.
        Op::Patch { .. } => "/set/props",
        _ => return value,
    };
    if let Some(props) = value.pointer_mut(pointer).and_then(Value::as_object_mut) {
        withhold_record_reference(props, visible);
    }
    value
}

fn redact_pre_images(pre_images: &BTreeMap<String, PreImage>, visible: &HashSet<String>) -> Value {
    let mut value = serde_json::to_value(pre_images).expect("pre-images serialize");
    if let Some(entries) = value.as_object_mut() {
        for entry in entries.values_mut() {
            if let Some(props) = entry.get_mut("props").and_then(Value::as_object_mut) {
                withhold_record_reference(props, visible);
            }
        }
    }
    value
}

async fn disclosed_actors(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    actors: impl IntoIterator<Item = String>,
) -> Result<HashMap<String, Value>> {
    let mut disclosed = HashMap::new();
    for actor in actors {
        if disclosed.contains_key(&actor) {
            continue;
        }
        let face = super::history::disclosed_actor_identity_in(tx, caller, &actor)
            .await?
            .map(|(id, display_name)| json!({ "id": id, "display_name": display_name }))
            .unwrap_or(Value::Null);
        disclosed.insert(actor, face);
    }
    Ok(disclosed)
}

// ---- shared guards -------------------------------------------------------

/// A canvas the caller may see, or the same "does not exist" every other
/// record read gives for hidden and missing records alike.
async fn require_canvas_in(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    tool: &str,
    canvas_id: &str,
    required: Capability,
) -> Result<()> {
    if !can_record_in(tx, caller, canvas_id, Capability::View).await? {
        return Err(Error::engine(format!(
            "{tool}: record {canvas_id} does not exist"
        )));
    }
    if !is_live_canvas(tx, canvas_id).await? {
        return Err(Error::engine(format!(
            "{tool}: record {canvas_id} is not a Document kind:canvas"
        )));
    }
    if required != Capability::View && !can_record_in(tx, caller, canvas_id, required).await? {
        return Err(Error::engine(format!(
            "{tool}: record {canvas_id} requires edit capability; caller has view capability"
        )));
    }
    Ok(())
}

async fn is_live_canvas(conn: &mut SqliteConnection, canvas_id: &str) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM records
          WHERE id=? AND type='Document' AND kind='canvas' AND deleted_at IS NULL)",
    )
    .bind(canvas_id)
    .fetch_one(&mut *conn)
    .await?)
}

// ---- read_canvas ---------------------------------------------------------

async fn read_canvas(db: Db, caller: Caller, mut arguments: Value) -> Result<Value> {
    let as_of = lens::take_as_of(READ_TOOL, &mut arguments)?;
    let args: ReadCanvasArgs = parse_args(READ_TOOL, arguments)?;
    match args {
        ReadCanvasArgs::GetScene {
            canvas_id,
            include_deleted,
        } => {
            let Some(selector) = as_of else {
                return get_scene(&db, None, &caller, &canvas_id, include_deleted, None).await;
            };
            let resolved = lens::resolve_as_of(&db, selector).await?;
            let scratch = crate::db::open_database(":memory:").await?;
            let result = async {
                crate::db::apply_schema(&scratch).await?;
                lens::replay_projection(&db, &scratch, resolved.resolved_content_seq).await?;
                let mut output = get_scene(
                    &db,
                    Some(&scratch),
                    &caller,
                    &canvas_id,
                    include_deleted,
                    Some(resolved.resolved_content_seq),
                )
                .await?;
                lens::echo_temporal(&mut output, &resolved);
                Ok(output)
            }
            .await;
            scratch.close().await;
            result
        }
        ReadCanvasArgs::Changes {
            canvas_id,
            after,
            limit,
        } => {
            if as_of.is_some() {
                return Err(Error::engine(
                    "read_canvas: as_of applies to get_scene only; changes is already a history read",
                ));
            }
            changes(&db, &caller, &canvas_id, &after, limit).await
        }
        ReadCanvasArgs::Describe { canvas_id } => {
            if as_of.is_some() {
                return Err(Error::engine(
                    "read_canvas: as_of applies to get_scene only; describe outlines the current scene",
                ));
            }
            // Describe deliberately reads through get_scene rather than
            // loading the scene again: the outline is then built from the
            // very values that read path redacted, so a withheld record
            // cannot reach the prose through a second, forgetful loader.
            let scene = get_scene(&db, None, &caller, &canvas_id, false, None).await?;
            let objects = scene
                .get("objects")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let version = scene
                .get("canvas_version")
                .and_then(Value::as_str)
                .and_then(canvas::CanvasVersion::parse)
                .unwrap_or(canvas::CanvasVersion(0));
            Ok(canvas::describe_scene(&canvas_id, version, &objects))
        }
    }
}

/// Authorization and record faces are always resolved LIVE, as the caller;
/// only the scene itself comes from the historical replay when `as_of` is
/// given. A face is "the record as it is now", which is what a card shows.
async fn get_scene(
    db: &Db,
    scene_source: Option<&Db>,
    caller: &Caller,
    canvas_id: &str,
    include_deleted: bool,
    resolved_content_seq: Option<i64>,
) -> Result<Value> {
    let mut tx = db.write_pool().begin().await?;
    require_canvas_in(&mut tx, caller, READ_TOOL, canvas_id, Capability::View).await?;
    let (objects, version) = match scene_source {
        None => (
            canvas::load_scene(&mut tx, canvas_id, include_deleted).await?,
            canvas::current_version(&mut tx, canvas_id).await?,
        ),
        Some(scratch) => {
            let mut historical = scratch.write_pool().begin().await?;
            let objects = canvas::load_scene(&mut historical, canvas_id, include_deleted).await?;
            let version = canvas::current_version(&mut historical, canvas_id).await?;
            historical.rollback().await?;
            (objects, version)
        }
    };
    let mut values: Vec<Value> = objects.iter().map(SceneObject::to_value).collect();
    let referenced = referenced_record_ids(&values, &[]);
    let visible = visible_ids_preloaded_in(&mut tx, caller, &referenced).await?;
    let mut faces = HashMap::new();
    for id in &visible {
        if let Some(face) = record_face(&mut tx, id).await? {
            faces.insert(id.clone(), face);
        }
    }
    // Built from the unredacted scene: after redaction a withheld card reads
    // "withheld" and could no longer resolve its own endpoint.
    let cards: HashMap<String, String> = objects
        .iter()
        .filter(|object| object.kind == ObjectKind::RecordCard)
        .filter_map(|object| {
            object
                .props
                .get("record_id")
                .and_then(Value::as_str)
                .map(|record| (object.id.clone(), record.to_owned()))
        })
        .collect();
    for object in &mut values {
        redact_object(object, &visible, &faces);
    }
    resolve_connector_semantics(&mut tx, &mut values, &cards, &visible).await?;
    tx.rollback().await?;
    let live = values
        .iter()
        .filter(|object| object.get("deleted") == Some(&Value::Bool(false)))
        .count();
    Ok(json!({
        "action": "get_scene",
        "version": SCENE_VERSION,
        "canvas_id": canvas_id,
        "canvas_version": version.encode(),
        "resolved_content_seq": resolved_content_seq,
        "include_deleted": include_deleted,
        "objects": values,
        "live_objects": live,
        "limits": {
            "ops_per_batch": canvas::MAX_OPS_PER_BATCH,
            "batch_bytes": canvas::MAX_BATCH_CANONICAL_BYTES,
            "live_objects": canvas::MAX_LIVE_OBJECTS,
        },
    }))
}

async fn changes(
    db: &Db,
    caller: &Caller,
    canvas_id: &str,
    after: &str,
    limit: Option<usize>,
) -> Result<Value> {
    let Some(after) = CanvasVersion::parse(after) else {
        return Err(Error::engine(
            "read_canvas: after must be a canvas:N token (canvas:0 for full history)",
        ));
    };
    let limit = limit.unwrap_or(DEFAULT_CHANGES_LIMIT);
    if limit == 0 || limit > MAX_CHANGES_LIMIT {
        return Err(Error::engine(format!(
            "read_canvas: limit must be 1-{MAX_CHANGES_LIMIT}"
        )));
    }
    let mut tx = db.write_pool().begin().await?;
    require_canvas_in(&mut tx, caller, READ_TOOL, canvas_id, Capability::View).await?;
    let head = canvas::current_version(&mut tx, canvas_id).await?;
    let rows = sqlx::query(
        "SELECT b.batch_id,b.actor,b.event_id,b.event_seq,e.payload,e.created_at
           FROM canvas_batches b JOIN content_events e ON e.id=b.event_id
          WHERE b.canvas_id=? AND b.event_seq>? ORDER BY b.event_seq LIMIT ?",
    )
    .bind(canvas_id)
    .bind(after.0)
    .bind(limit as i64 + 1)
    .fetch_all(&mut *tx)
    .await?;
    let more = rows.len() > limit;
    let mut batches = Vec::with_capacity(rows.len().min(limit));
    let mut referenced = BTreeSet::new();
    let mut actors = Vec::new();
    for row in rows.iter().take(limit) {
        let payload: Option<String> = row.try_get("payload")?;
        let stored: StoredBatch = serde_json::from_str(payload.as_deref().unwrap_or("null"))
            .map_err(|error| {
                Error::engine(format!("canvas batch payload is malformed: {error}"))
            })?;
        for id in referenced_record_ids(&[], &stored.ops) {
            referenced.insert(id);
        }
        if let Some(actor) = row.try_get::<Option<String>, _>("actor")? {
            actors.push(actor);
        }
        batches.push((
            row.try_get::<String, _>("batch_id")?,
            row.try_get::<Option<String>, _>("actor")?,
            row.try_get::<String, _>("event_id")?,
            row.try_get::<i64, _>("event_seq")?,
            row.try_get::<String, _>("created_at")?,
            stored,
        ));
    }
    let referenced = referenced.into_iter().collect::<Vec<_>>();
    let visible = visible_ids_preloaded_in(&mut tx, caller, &referenced).await?;
    let disclosed = disclosed_actors(&mut tx, caller, actors).await?;
    tx.rollback().await?;
    let batches = batches
        .into_iter()
        .map(|(batch_id, actor, event_id, event_seq, at, stored)| {
            let ops = stored
                .ops
                .iter()
                .map(|op| redact_op(op, &visible))
                .collect::<Vec<_>>();
            json!({
                "batch_id": batch_id,
                "event_id": event_id,
                "event_seq": event_seq,
                "canvas_version": CanvasVersion(event_seq).encode(),
                "actor": actor.as_ref().and_then(|actor| disclosed.get(actor).cloned()).unwrap_or(Value::Null),
                "at": at,
                "origin": stored.origin,
                "base_version": stored.base_version,
                "ops": ops,
                "pre_images": redact_pre_images(&stored.pre_images, &visible),
                "detached": stored.detached,
            })
        })
        .collect::<Vec<_>>();
    let next_after = batches
        .last()
        .and_then(|batch| batch.get("canvas_version").cloned())
        .unwrap_or_else(|| Value::String(after.encode()));
    Ok(json!({
        "action": "changes",
        "version": CHANGES_VERSION,
        "canvas_id": canvas_id,
        "after": after.encode(),
        "canvas_version": head.encode(),
        "batches": batches,
        "more": more,
        "next_after": next_after,
    }))
}

// ---- manage_canvas -------------------------------------------------------

/// commit_batch's refusal envelope.
fn rejected(
    batch_id: Option<&str>,
    canvas_version: Option<CanvasVersion>,
    refusal: &Refusal,
) -> Value {
    refused("commit_batch", batch_id, canvas_version, refusal)
}

fn refused(
    action: &str,
    batch_id: Option<&str>,
    canvas_version: Option<CanvasVersion>,
    refusal: &Refusal,
) -> Value {
    let mut error = json!({ "code": refusal.code, "message": refusal.message });
    if let Some(id) = &refusal.object_id {
        error["object_id"] = json!(id);
    }
    if let Some(limit) = refusal.limit {
        error["limit"] = json!(limit);
    }
    json!({
        "action": action,
        "version": RESULT_VERSION,
        "outcome": "rejected",
        "batch_id": batch_id,
        "canvas_version": canvas_version.map(CanvasVersion::encode),
        "objects": {},
        "conflicts": [],
        "error": error,
    })
}

fn refusal(code: &'static str, message: impl Into<String>) -> Refusal {
    Refusal {
        code,
        object_id: None,
        message: message.into(),
        limit: None,
    }
}

struct Conflict {
    id: String,
    group: Option<&'static str>,
    code: &'static str,
    current: Option<Value>,
    competing_seq: Option<i64>,
}

/// The groups an op touches, so replay can reproduce the versions a batch
/// left without re-reading the scene.
fn touched_groups(op: &Op) -> (bool, bool) {
    match op {
        Op::Create { .. } | Op::Delete { .. } | Op::Restore { .. } => (true, true),
        Op::Patch { set, .. } => (set.touches_geometry(), set.touches_content()),
    }
}

fn versions_after(
    seq: i64,
    ops: &[Op],
    pre_images: &BTreeMap<String, PreImage>,
    detached: &[String],
) -> Value {
    let mut objects = Map::new();
    for op in ops {
        let (geometry, content) = touched_groups(op);
        let geometry = geometry || detached.iter().any(|id| id == op.object_id());
        let pre = pre_images.get(op.object_id());
        let geometry_seq = if geometry {
            seq
        } else {
            pre.map_or(seq, |pre| pre.geometry)
        };
        let content_seq = if content {
            seq
        } else {
            pre.map_or(seq, |pre| pre.content)
        };
        objects.insert(
            op.object_id().to_owned(),
            json!({
                "geometry": CanvasVersion(geometry_seq).encode(),
                "content": CanvasVersion(content_seq).encode(),
            }),
        );
    }
    // Children detached by a frame delete moved too, without an op of their
    // own; a client holding their old geometry token must learn the new one.
    for id in detached {
        if objects.contains_key(id) {
            continue;
        }
        let content_seq = pre_images.get(id).map_or(seq, |pre| pre.content);
        objects.insert(
            id.clone(),
            json!({
                "geometry": CanvasVersion(seq).encode(),
                "content": CanvasVersion(content_seq).encode(),
            }),
        );
    }
    Value::Object(objects)
}

fn expected_version(expected: &Expected, group: &str) -> Option<i64> {
    let token = match group {
        "geometry" => expected.geometry.as_deref(),
        _ => expected.content.as_deref(),
    }?;
    CanvasVersion::parse(token).map(|version| version.0)
}

/// Compare every op's `expected` against the snapshot and collect the
/// pre-image the event will carry. Runs before the dry fold so a stale
/// precondition is reported as a conflict, never as a referential refusal.
async fn compare_and_preimage(
    tx: &mut Transaction<'_, Sqlite>,
    canvas_id: &str,
    ops: &[Op],
) -> Result<(Vec<Conflict>, BTreeMap<String, PreImage>)> {
    let mut conflicts = Vec::new();
    let mut pre_images = BTreeMap::new();
    for op in ops {
        let (id, expected) = match op {
            Op::Create { .. } => continue,
            Op::Patch { id, expected, .. }
            | Op::Delete { id, expected }
            | Op::Restore { id, expected } => (id, expected),
        };
        let Some(current) = canvas::load_object(tx, canvas_id, id).await? else {
            // Referential; the dry fold names it as `unknown_object`.
            continue;
        };
        let current_versions = json!({
            "geometry": CanvasVersion(current.geometry_seq).encode(),
            "content": CanvasVersion(current.content_seq).encode(),
        });
        if current.deleted && !matches!(op, Op::Restore { .. }) {
            conflicts.push(Conflict {
                id: id.clone(),
                group: None,
                code: "object_deleted",
                current: Some(current_versions),
                competing_seq: Some(current.geometry_seq),
            });
            continue;
        }
        let mut stale = false;
        for (group, actual) in [
            ("geometry", current.geometry_seq),
            ("content", current.content_seq),
        ] {
            if let Some(expected_seq) = expected_version(expected, group) {
                if expected_seq != actual {
                    stale = true;
                    conflicts.push(Conflict {
                        id: id.clone(),
                        group: Some(group),
                        code: "version_mismatch",
                        current: Some(current_versions.clone()),
                        competing_seq: Some(actual),
                    });
                }
            }
        }
        if stale {
            continue;
        }
        let mut pre = PreImage {
            geometry: current.geometry_seq,
            content: current.content_seq,
            ..PreImage::default()
        };
        match op {
            Op::Patch { set, .. } => {
                if set.x.is_some() {
                    pre.x = Some(current.x);
                }
                if set.y.is_some() {
                    pre.y = Some(current.y);
                }
                if set.w.is_some() {
                    pre.w = Some(current.w);
                }
                if set.h.is_some() {
                    pre.h = Some(current.h);
                }
                if set.z.is_some() {
                    pre.z = Some(current.z.clone());
                }
                if set.parent.is_some() {
                    pre.parent = Some(current.parent.clone());
                }
                if let Some(patch) = &set.props {
                    let (_, previous) = canvas::merge_props(&current.props, patch);
                    pre.props = Some(previous);
                }
            }
            Op::Delete { .. } => pre.deleted = Some(false),
            Op::Restore { .. } => {
                pre.deleted = Some(true);
                pre.parent = Some(current.parent.clone());
            }
            Op::Create { .. } => unreachable!("creates carry no pre-image"),
        }
        pre_images.insert(id.clone(), pre);
    }
    Ok((conflicts, pre_images))
}

async fn manage_canvas(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let batch = match parse_args(WRITE_TOOL, arguments)? {
        ManageCanvasArgs::CommitBatch { batch } => batch,
        ManageCanvasArgs::AssertConnector {
            canvas_id,
            object_id,
            relationship,
            note,
            expected,
        } => {
            return assert_connector(
                db,
                caller,
                canvas_id,
                object_id,
                relationship,
                note,
                expected,
            )
            .await;
        }
        ManageCanvasArgs::Promote {
            canvas_id,
            items,
            links,
            dry_run,
            expected,
            plan_digest,
            reason,
        } => {
            return promote(
                db,
                caller,
                canvas_id,
                items,
                links,
                dry_run,
                expected,
                plan_digest,
                reason,
            )
            .await;
        }
    };
    let batch_id = batch
        .get("batch_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let envelope: BatchEnvelope = match serde_json::from_value(batch) {
        Ok(envelope) => envelope,
        Err(error) => {
            return Ok(rejected(
                batch_id.as_deref(),
                None,
                &refusal("invalid_envelope", format!("batch does not parse: {error}")),
            ))
        }
    };
    if let Err(FoldError::Refused(refused)) = canvas::validate_envelope(&envelope) {
        return Ok(rejected(Some(&envelope.batch_id), None, &refused));
    }
    let canvas_id = envelope.canvas_id.clone();

    // 1. Preflight outside the write lock: the canvas must be an editable
    //    canvas and every record card's record must be visible. Nothing here
    //    substitutes for the in-transaction checks below.
    if !can_record(&db, &caller, &canvas_id, Capability::View).await?
        || !is_live_canvas_pool(&db, &canvas_id).await?
    {
        return Ok(rejected(
            Some(&envelope.batch_id),
            None,
            &refusal(
                "unknown_canvas",
                format!("record {canvas_id} does not exist"),
            ),
        ));
    }
    if !can_record(&db, &caller, &canvas_id, Capability::Edit).await? {
        return Ok(rejected(
            Some(&envelope.batch_id),
            None,
            &refusal(
                "permission_denied",
                format!("the authenticated principal may not edit canvas {canvas_id}"),
            ),
        ));
    }
    let card_records = referenced_record_ids(&[], &envelope.ops);
    for record_id in &card_records {
        if !can_record(&db, &caller, record_id, Capability::View).await? {
            return Ok(rejected(
                Some(&envelope.batch_id),
                None,
                &Refusal {
                    code: "record_not_visible",
                    object_id: envelope
                        .ops
                        .iter()
                        .find(|op| matches!(op, Op::Create { object } if record_id_of_card(&object.props) == Some(record_id)))
                        .map(|op| op.object_id().to_owned()),
                    message: format!("record {record_id} does not exist"),
                    limit: None,
                },
            ));
        }
    }

    let mut tx = crate::db::begin_write(db.write_pool()).await?;

    // 2. Re-check as the authenticated principal inside the same snapshot as
    //    the append; the preflight above is a courtesy, not the decision.
    if !can_record_in(&mut tx, &caller, &canvas_id, Capability::View).await?
        || !is_live_canvas(&mut tx, &canvas_id).await?
    {
        return Ok(rejected(
            Some(&envelope.batch_id),
            None,
            &refusal(
                "unknown_canvas",
                format!("record {canvas_id} does not exist"),
            ),
        ));
    }
    if !can_record_in(&mut tx, &caller, &canvas_id, Capability::Edit).await? {
        return Ok(rejected(
            Some(&envelope.batch_id),
            None,
            &refusal(
                "permission_denied",
                format!("the authenticated principal may not edit canvas {canvas_id}"),
            ),
        ));
    }
    let visible_cards = visible_ids_preloaded_in(&mut tx, &caller, &card_records).await?;
    if let Some(hidden) = card_records.iter().find(|id| !visible_cards.contains(*id)) {
        return Ok(rejected(
            Some(&envelope.batch_id),
            None,
            &refusal(
                "record_not_visible",
                format!("record {hidden} does not exist"),
            ),
        ));
    }
    let head = canvas::current_version(&mut tx, &canvas_id).await?;
    let digest = canvas::ops_digest(&envelope.ops)?;

    // 3. Idempotency: the ledger is the authority. Same actor and same ops
    //    replays; anything else with this batch_id is a different intent.
    let ledger = sqlx::query(
        "SELECT actor,event_id,event_seq,ops_sha256 FROM canvas_batches
          WHERE canvas_id=? AND batch_id=?",
    )
    .bind(&canvas_id)
    .bind(&envelope.batch_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(ledger) = ledger {
        let same_actor =
            ledger.try_get::<Option<String>, _>("actor")?.as_deref() == Some(caller.actor());
        let same_ops = ledger.try_get::<String, _>("ops_sha256")? == digest;
        if !(same_actor && same_ops) {
            return Ok(rejected(
                Some(&envelope.batch_id),
                Some(head),
                &refusal(
                    "batch_id_reused",
                    "this batch_id was already committed with different ops or by a different actor",
                ),
            ));
        }
        let event_id: String = ledger.try_get("event_id")?;
        let event_seq: i64 = ledger.try_get("event_seq")?;
        let payload: Option<String> =
            sqlx::query_scalar("SELECT payload FROM content_events WHERE id=?")
                .bind(&event_id)
                .fetch_one(&mut *tx)
                .await?;
        let stored: StoredBatch = serde_json::from_str(payload.as_deref().unwrap_or("null"))?;
        // A replay commits nothing.
        tx.rollback().await?;
        return Ok(json!({
            "action": "commit_batch",
            "version": RESULT_VERSION,
            "outcome": "replayed",
            "batch_id": envelope.batch_id,
            "canvas_version": CanvasVersion(event_seq).encode(),
            "event_id": event_id,
            "objects": versions_after(event_seq, &stored.ops, &stored.pre_images, &stored.detached),
            "conflicts": [],
        }));
    }

    // 4. Compare-and-set at the granularity each group moves at.
    let (conflicts, pre_images) = compare_and_preimage(&mut tx, &canvas_id, &envelope.ops).await?;
    if !conflicts.is_empty() {
        let mut items = Vec::with_capacity(conflicts.len());
        for conflict in conflicts {
            let competing_actor = match conflict.competing_seq {
                Some(seq) => {
                    let actor: Option<String> = sqlx::query_scalar(
                        "SELECT actor FROM canvas_batches WHERE canvas_id=? AND event_seq=?",
                    )
                    .bind(&canvas_id)
                    .bind(seq)
                    .fetch_optional(&mut *tx)
                    .await?
                    .flatten();
                    match actor {
                        Some(actor) => super::history::disclosed_actor_identity_in(
                            &mut tx, &caller, &actor,
                        )
                        .await?
                        .map(|(id, display_name)| json!({ "id": id, "display_name": display_name }))
                        .unwrap_or(Value::Null),
                        None => Value::Null,
                    }
                }
                None => Value::Null,
            };
            let mut item = json!({ "id": conflict.id, "code": conflict.code, "competing_actor": competing_actor });
            if let Some(group) = conflict.group {
                item["group"] = json!(group);
            }
            if let Some(current) = conflict.current {
                item["current"] = current;
            }
            items.push(item);
        }
        tx.rollback().await?;
        return Ok(json!({
            "action": "commit_batch",
            "version": RESULT_VERSION,
            "outcome": "conflict",
            "batch_id": envelope.batch_id,
            "canvas_version": head.encode(),
            "base_version": envelope.base_version,
            "objects": {},
            "conflicts": items,
            "error": { "code": "precondition_failed", "message": "one or more preconditions no longer hold; nothing was written" },
        }));
    }

    // 5. Dry fold inside a savepoint: the exact referential rules the
    //    projector enforces, reported as a structured refusal instead of an
    //    engine error, then rolled back so the real fold starts clean.
    sqlx::query("SAVEPOINT canvas_dry_fold")
        .execute(&mut *tx)
        .await?;
    // `of` rather than a literal `Client`: validate_envelope has already
    // refused an engine-authored origin from this seam, so this is Client
    // today, and it stays correct if an engine path ever folds here.
    let dry = canvas::apply_batch(
        &mut tx,
        &canvas_id,
        head.0 + 1,
        &envelope.ops,
        canvas::PropsAuthority::of(envelope.origin.kind),
    )
    .await;
    sqlx::query("ROLLBACK TO SAVEPOINT canvas_dry_fold")
        .execute(&mut *tx)
        .await?;
    sqlx::query("RELEASE SAVEPOINT canvas_dry_fold")
        .execute(&mut *tx)
        .await?;
    let detached: Vec<Detached> = match dry {
        Ok(detached) => detached,
        Err(FoldError::Refused(refused)) => {
            tx.rollback().await?;
            return Ok(rejected(Some(&envelope.batch_id), Some(head), &refused));
        }
        Err(FoldError::Engine(error)) => return Err(error),
    };
    // Detached children that existed before this batch get a pre-image so
    // the change feed can invert the detach; batch-created ones are ops.
    let mut pre_images = pre_images;
    let op_ids = envelope
        .ops
        .iter()
        .map(|op| op.object_id().to_owned())
        .collect::<HashSet<_>>();
    let mut detached_ids = Vec::new();
    for child in &detached {
        if !detached_ids.contains(&child.id) {
            detached_ids.push(child.id.clone());
        }
        if op_ids.contains(&child.id) || pre_images.contains_key(&child.id) {
            continue;
        }
        pre_images.insert(
            child.id.clone(),
            PreImage {
                geometry: child.geometry,
                content: child.content,
                parent: Some(Some(child.frame_id.clone())),
                ..PreImage::default()
            },
        );
    }

    // 6. Append; the projector folds on this same transaction.
    let stored = StoredBatch {
        version: BATCH_VERSION.into(),
        batch_id: envelope.batch_id.clone(),
        base_version: envelope.base_version.clone(),
        origin: envelope.origin.clone(),
        ops: envelope.ops.clone(),
        ops_sha256: digest,
        pre_images: pre_images.clone(),
        detached: detached_ids.clone(),
    };
    let event = append_in(
        &db,
        &mut tx,
        AppendSpec {
            record_id: canvas_id.clone(),
            event_type: CANVAS_BATCH_EVENT_TYPE.into(),
            payload: serde_json::to_value(&stored)?,
            actor: Some(caller.actor().into()),
        },
    )
    .await?;
    let objects = versions_after(event.local_seq, &envelope.ops, &pre_images, &detached_ids);
    db.commit_content(tx).await?;
    Ok(json!({
        "action": "commit_batch",
        "version": RESULT_VERSION,
        "outcome": "committed",
        "batch_id": envelope.batch_id,
        "canvas_version": CanvasVersion(event.local_seq).encode(),
        "event_id": event.id,
        "objects": objects,
        "conflicts": [],
        "write_receipt": {
            "kind": "content_event",
            "event": {
                "seq": event.local_seq,
                "event_id": event.id,
                "record_id": event.record_id,
                "event_type": event.event_type,
                "created_at": event.created_at,
            }
        },
    }))
}

/// `manage_canvas.assert_connector` — promote a decorative connector between
/// two record cards into a governed link.
///
/// The link write and the canvas batch that records it share one transaction
/// and one reserved action attestation, so `inspect_action_attestation` can
/// answer "which canvas gesture asserted this link". The connector's
/// `semantic.status` only ever stores `proposed` or `asserted`; `broken` is
/// derived at read time from whether the link row still exists, because
/// nothing hooks link removal to author a compensating batch (E3).
async fn assert_connector(
    db: Db,
    caller: Caller,
    canvas_id: String,
    object_id: String,
    relationship: String,
    note: Option<String>,
    expected: Option<Expected>,
) -> Result<Value> {
    let deny = |refusal: &Refusal| refused("assert_connector", None, None, refusal);

    if relationship.trim().is_empty() || relationship.len() > canvas::MAX_ID_BYTES {
        return Ok(deny(&refusal(
            "invalid_envelope",
            "relationship must be a non-empty token",
        )));
    }

    // Preflight outside the write lock; nothing here substitutes for the
    // in-transaction checks below.
    if !can_record(&db, &caller, &canvas_id, Capability::View).await?
        || !is_live_canvas_pool(&db, &canvas_id).await?
    {
        return Ok(deny(&refusal(
            "unknown_canvas",
            format!("record {canvas_id} does not exist"),
        )));
    }

    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    if !is_live_canvas(&mut tx, &canvas_id).await? {
        tx.rollback().await?;
        return Ok(deny(&refusal(
            "unknown_canvas",
            format!("record {canvas_id} does not exist"),
        )));
    }
    if !can_record_in(&mut tx, &caller, &canvas_id, Capability::Edit).await? {
        tx.rollback().await?;
        return Ok(deny(&refusal(
            "permission_denied",
            format!("the authenticated principal may not edit canvas {canvas_id}"),
        )));
    }

    let connector = match canvas::load_object(&mut tx, &canvas_id, &object_id).await? {
        Some(object) if !object.deleted => object,
        Some(_) => {
            tx.rollback().await?;
            return Ok(deny(&Refusal {
                object_id: Some(object_id.clone()),
                ..refusal("object_deleted", "this connector is tombstoned")
            }));
        }
        None => {
            tx.rollback().await?;
            return Ok(deny(&Refusal {
                object_id: Some(object_id.clone()),
                ..refusal(
                    "unknown_object",
                    format!("canvas {canvas_id} has no object {object_id}"),
                )
            }));
        }
    };
    // A real precondition, checked against what the caller last read. The
    // batch this action writes pins the connector's own content version, but
    // that version is read inside this same transaction and so can only ever
    // agree with itself; a client whose scene is stale — whose connector now
    // joins two different cards than the one it saw — would otherwise assert
    // a governed link between records it never chose.
    for (group, expected, current) in [
        (
            "content",
            expected.as_ref().and_then(|pins| pins.content.clone()),
            connector.content_seq,
        ),
        (
            "geometry",
            expected.as_ref().and_then(|pins| pins.geometry.clone()),
            connector.geometry_seq,
        ),
    ] {
        let Some(pinned) = expected else { continue };
        if CanvasVersion::parse(&pinned) != Some(CanvasVersion(current)) {
            let head = canvas::current_version(&mut tx, &canvas_id).await?;
            tx.rollback().await?;
            let mut conflict = refused(
                "assert_connector",
                None,
                Some(head),
                &Refusal {
                    object_id: Some(object_id.clone()),
                    ..refusal(
                        "version_mismatch",
                        format!("the connector's {group} has moved since you read it"),
                    )
                },
            );
            conflict["outcome"] = json!("conflict");
            conflict["conflicts"] = json!([{
                "id": object_id,
                "group": group,
                "code": "version_mismatch",
                "current": {
                    "geometry": CanvasVersion(connector.geometry_seq).encode(),
                    "content": CanvasVersion(connector.content_seq).encode(),
                },
            }]);
            return Ok(conflict);
        }
    }

    if connector.kind != ObjectKind::Connector {
        tx.rollback().await?;
        return Ok(deny(&Refusal {
            object_id: Some(object_id.clone()),
            ..refusal(
                "invalid_envelope",
                "only a connector can be asserted as a link",
            )
        }));
    }

    // Both ends must be anchored to live record cards: a free point names no
    // record, so there is nothing to relate.
    let mut records: Vec<String> = Vec::new();
    for end in ["from", "to"] {
        let anchor = connector
            .props
            .get(end)
            .and_then(Value::as_object)
            .and_then(|endpoint| endpoint.get("object"))
            .and_then(Value::as_str);
        let Some(anchor) = anchor else {
            tx.rollback().await?;
            return Ok(deny(&Refusal {
                object_id: Some(object_id.clone()),
                ..refusal(
                    "invalid_envelope",
                    format!("props.{end} must anchor to a record card to be asserted"),
                )
            }));
        };
        let card = match canvas::load_object(&mut tx, &canvas_id, anchor).await? {
            Some(card) if !card.deleted && card.kind == ObjectKind::RecordCard => card,
            _ => {
                tx.rollback().await?;
                return Ok(deny(&Refusal {
                    object_id: Some(anchor.to_owned()),
                    ..refusal(
                        "unknown_object",
                        format!("props.{end} must anchor to a live record card"),
                    )
                }));
            }
        };
        let Some(record_id) = card.props.get("record_id").and_then(Value::as_str) else {
            tx.rollback().await?;
            return Ok(deny(&Refusal {
                object_id: Some(anchor.to_owned()),
                ..refusal("invalid_envelope", "that record card names no record")
            }));
        };
        records.push(record_id.to_owned());
    }
    let (source_record, target_record) = (records[0].clone(), records[1].clone());

    // Authorization for the link itself comes first, before any branch that
    // could report something derived from these two records. `manage_links`
    // thresholds: Edit on the source, View on the target (note §6). Ordering
    // is the disclosure control here, not just the check: the replay branch
    // below returns a link id, and a content-owned id spells
    // `lnk:{source}:{target}:{relationship}`, so reaching it without View on
    // both records would hand a canvas editor two record ids that get_scene
    // deliberately withholds. The same-record refusal is ordered after these
    // for the same reason: whether two withheld cards name one record or two
    // is itself a fact about records the caller may not see.
    if !can_record_in(&mut tx, &caller, &source_record, Capability::Edit).await? {
        tx.rollback().await?;
        return Ok(deny(&refusal(
            "permission_denied",
            "asserting this connector needs Edit on the record its source card names",
        )));
    }
    if !can_record_in(&mut tx, &caller, &target_record, Capability::View).await? {
        tx.rollback().await?;
        return Ok(deny(&refusal(
            "record_not_visible",
            "asserting this connector needs View on the record its target card names",
        )));
    }

    if source_record == target_record {
        tx.rollback().await?;
        return Ok(deny(&Refusal {
            object_id: Some(object_id.clone()),
            ..refusal(
                "invalid_envelope",
                "a connector must join two different records",
            )
        }));
    }

    // Idempotency: re-asserting a connector that already carries this
    // relationship and whose link still exists is `replayed`, never a second
    // link (E3).
    let already = connector
        .props
        .get("semantic")
        .and_then(Value::as_object)
        .filter(|semantic| {
            semantic.get("relationship").and_then(Value::as_str) == Some(relationship.as_str())
                && semantic.get("status").and_then(Value::as_str) == Some("asserted")
        })
        .and_then(|semantic| semantic.get("link_id").and_then(Value::as_str))
        .map(str::to_owned);
    // A connector already asserted under a *different* live relationship is
    // refused rather than overwritten. Overwriting would replace `semantic`
    // wholesale, leaving the first governed link in place with nothing on the
    // canvas recording it, and its promotion attestation unreachable from the
    // scene that created it. Retract through `manage_links.remove` first.
    if let Some(existing) = connector
        .props
        .get("semantic")
        .and_then(Value::as_object)
        .filter(|semantic| semantic.get("status").and_then(Value::as_str) == Some("asserted"))
        .and_then(|semantic| semantic.get("relationship").and_then(Value::as_str))
        .filter(|existing| *existing != relationship)
        .map(str::to_owned)
    {
        if link_exists_in(&mut tx, &source_record, &target_record, &existing).await? {
            tx.rollback().await?;
            return Ok(deny(&Refusal {
                object_id: Some(object_id.clone()),
                ..refusal(
                    "invalid_precondition",
                    format!(
                        "this connector is already asserted as {existing}; \
                         remove that link before asserting another"
                    ),
                )
            }));
        }
    }

    if let Some(link_id) = already {
        if link_exists_in(&mut tx, &source_record, &target_record, &relationship).await? {
            let head = canvas::current_version(&mut tx, &canvas_id).await?;
            tx.rollback().await?;
            return Ok(json!({
                "action": "assert_connector",
                "version": RESULT_VERSION,
                "outcome": "replayed",
                "canvas_version": head.encode(),
                "object_id": object_id,
                "relationship": relationship,
                "link_id": link_id,
                "objects": {},
                "conflicts": [],
            }));
        }
    }

    // One reserved identity for the link and the batch that records it.
    let draft = crate::provenance::reserve_action_attestation()?;
    let minted = if super::links::relationship_owned_in(
        &mut tx,
        &source_record,
        &target_record,
        &relationship,
    )
    .await?
    {
        let receipt = crate::relationship::legacy::mutate_from_canvas_in(
            &mut tx,
            &caller,
            &source_record,
            &target_record,
            &relationship,
            note.clone(),
            &draft,
        )
        .await?;
        // The relationship route's compatibility row is projected from the
        // assertion frontier, not written here, so it is not yet visible in
        // this transaction; this is the id that projection will carry.
        match (
            receipt
                .get("relationship_origin_db_id")
                .and_then(Value::as_str),
            receipt.get("relationship_id").and_then(Value::as_str),
        ) {
            (Some(origin), Some(id)) => Some(format!("rel:{origin}:{id}")),
            _ => None,
        }
    } else {
        append_in(
            &db,
            &mut tx,
            AppendSpec {
                record_id: source_record.clone(),
                event_type: "link.added".into(),
                payload: serde_json::to_value(crate::events::LinkAddedPayload {
                    id: None,
                    source_id: source_record.clone(),
                    target_id: target_record.clone(),
                    relationship: relationship.clone(),
                    note: note.clone(),
                })?,
                actor: Some(caller.actor().into()),
            },
        )
        .await?;
        Some(format!(
            "lnk:{source_record}:{target_record}:{relationship}"
        ))
    };

    // Prefer the id of the row that actually occupies this triple. Two reasons:
    // a row may already occupy it — a federated `lnk:fed:…` link, or a
    // content-owned row the relationship projection therefore declines to
    // replace — in which case the id this route would mint names nothing.
    // Falling back to the minted id covers the relationship route, whose own
    // row is projected after this transaction and so cannot be read back yet.
    // Either way the result is bounded: the content-owned spelling
    // `lnk:{source}:{target}:{relationship}` can exceed MAX_ID_BYTES for a
    // long token, which the fold would otherwise refuse as an opaque engine
    // error after the link had already been written. A link we cannot cite by
    // id is recorded as asserted with a null id, which is honest; a citation
    // that resolves to nothing is not.
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT id FROM links WHERE source_id=? AND target_id=? AND relationship=?",
    )
    .bind(&source_record)
    .bind(&target_record)
    .bind(&relationship)
    .fetch_optional(&mut *tx)
    .await?;
    let link_id: Option<String> = existing
        .or(minted)
        .filter(|id: &String| id.len() <= canvas::MAX_ID_BYTES);

    // The assertion batch. `expected` pins the connector's content version so
    // a concurrent edit to the same group is a conflict rather than a silent
    // overwrite, exactly as an ordinary patch would be.
    let mut props_patch = Map::new();
    props_patch.insert(
        "semantic".into(),
        json!({ "relationship": relationship, "link_id": link_id, "status": "asserted" }),
    );
    debug_assert!(props_patch["semantic"]["status"] == json!("asserted"));
    let ops = vec![Op::Patch {
        id: object_id.clone(),
        expected: Expected {
            geometry: None,
            content: Some(CanvasVersion(connector.content_seq).encode()),
        },
        set: PatchSet {
            props: Some(props_patch),
            ..PatchSet::default()
        },
    }];
    let mut previous = Map::new();
    previous.insert(
        "semantic".into(),
        connector
            .props
            .get("semantic")
            .cloned()
            .unwrap_or(Value::Null),
    );
    let mut pre_images = BTreeMap::new();
    pre_images.insert(
        object_id.clone(),
        PreImage {
            geometry: connector.geometry_seq,
            content: connector.content_seq,
            props: Some(previous),
            ..PreImage::default()
        },
    );
    let stored = StoredBatch {
        version: BATCH_VERSION.into(),
        batch_id: uuid::Uuid::new_v4().to_string(),
        base_version: None,
        origin: canvas::Origin {
            kind: canvas::OriginKind::Assertion,
            gesture: None,
            undo_of: None,
            note: None,
        },
        ops: ops.clone(),
        ops_sha256: canvas::ops_digest(&ops)?,
        pre_images: pre_images.clone(),
        detached: Vec::new(),
    };
    let event = append_in(
        &db,
        &mut tx,
        AppendSpec {
            record_id: canvas_id.clone(),
            event_type: CANVAS_BATCH_EVENT_TYPE.into(),
            payload: serde_json::to_value(&stored)?,
            actor: Some(caller.actor().into()),
        },
    )
    .await?;
    let objects = versions_after(event.local_seq, &ops, &pre_images, &[]);
    crate::provenance::issue_reserved_pending_action_in(&mut tx, draft).await?;
    db.commit_content(tx).await?;

    Ok(json!({
        "action": "assert_connector",
        "version": RESULT_VERSION,
        "outcome": "committed",
        "batch_id": stored.batch_id,
        "canvas_version": CanvasVersion(event.local_seq).encode(),
        "event_id": event.id,
        "object_id": object_id,
        "relationship": relationship,
        "link_id": link_id,
        "source_id": source_record,
        "target_id": target_record,
        "objects": objects,
        "conflicts": [],
    }))
}

/// Does a link row still join these two records with this relationship?
///
/// Ignores `links.id` deliberately, so it answers the same question for a
/// content-owned `lnk:` row and a relationship-owned `rel:` projection.
async fn link_exists_in(
    tx: &mut Transaction<'static, Sqlite>,
    source_id: &str,
    target_id: &str,
    relationship: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM links WHERE source_id=? AND target_id=? AND relationship=?)",
    )
    .bind(source_id)
    .bind(target_id)
    .bind(relationship)
    .fetch_one(&mut **tx)
    .await?)
}

/// The plan-required promotion boundary: turn provisional canvas objects into
/// governed records, in one transaction, under one action attestation.
///
/// `dry_run: true` assesses every item against the current scene and returns a
/// `plan_digest` binding the canvas version, each promoted object's versions,
/// and the planned records and links. `dry_run: false` requires that digest
/// back; any drift is `Error::Conflict` and writes nothing, so what was
/// previewed is exactly what is committed.
#[allow(clippy::too_many_arguments)]
async fn promote(
    db: Db,
    caller: Caller,
    canvas_id: String,
    items: Vec<PromoteItem>,
    links: Vec<PromoteLink>,
    dry_run: bool,
    expected: Option<PromoteExpected>,
    plan_digest: Option<String>,
    reason: String,
) -> Result<Value> {
    let deny = |refusal: &Refusal| {
        let mut value = refused("promote", None, None, refusal);
        value["version"] = json!(PROMOTE_VERSION);
        value
    };

    if reason.trim().is_empty() {
        return Ok(deny(&refusal(
            "invalid_envelope",
            "promote requires a reason",
        )));
    }
    if items.is_empty() {
        return Ok(deny(&refusal(
            "invalid_envelope",
            "promote needs at least one item",
        )));
    }
    if items.len() > MAX_PROMOTE_ITEMS {
        return Ok(deny(&Refusal {
            limit: Some("promote_items"),
            ..refusal(
                "limit_exceeded",
                format!("promote takes at most {MAX_PROMOTE_ITEMS} items"),
            )
        }));
    }
    let mut seen = BTreeSet::new();
    for item in &items {
        if !seen.insert(item.object_id.clone()) {
            return Ok(deny(&Refusal {
                object_id: Some(item.object_id.clone()),
                ..refusal(
                    "duplicate_object",
                    "an object may be promoted at most once per plan",
                )
            }));
        }
    }

    if !can_record(&db, &caller, &canvas_id, Capability::View).await?
        || !is_live_canvas_pool(&db, &canvas_id).await?
    {
        return Ok(deny(&refusal(
            "unknown_canvas",
            format!("record {canvas_id} does not exist"),
        )));
    }

    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    if !is_live_canvas(&mut tx, &canvas_id).await? {
        tx.rollback().await?;
        return Ok(deny(&refusal(
            "unknown_canvas",
            format!("record {canvas_id} does not exist"),
        )));
    }
    if !can_record_in(&mut tx, &caller, &canvas_id, Capability::Edit).await? {
        tx.rollback().await?;
        return Ok(deny(&refusal(
            "permission_denied",
            format!("the authenticated principal may not edit canvas {canvas_id}"),
        )));
    }

    // Assess every item against the scene as it is now.
    let head = canvas::current_version(&mut tx, &canvas_id).await?;
    let canvas_stale = expected
        .as_ref()
        .is_some_and(|pins| pins.canvas_version != head.encode());
    let mut assessments: Vec<Value> = Vec::new();
    let mut objects: Vec<SceneObject> = Vec::new();
    let mut all_accept = true;
    for item in &items {
        let loaded = canvas::load_object(&mut tx, &canvas_id, &item.object_id).await?;
        // An object the caller pinned a version for is one they had seen, so
        // its disappearance, tombstoning or conversion since is drift rather
        // than an incoherent plan -- and drift must read as stale, because
        // that is what the plan runtime turns into a 409.
        let pinned_by_caller = expected
            .as_ref()
            .is_some_and(|pins| pins.objects.contains_key(&item.object_id));
        let drift = if pinned_by_caller {
            "would_stale"
        } else {
            "would_conflict"
        };
        let (status, note) = match &loaded {
            None => (drift, "no such object on this canvas"),
            Some(object) if object.deleted => (drift, "this object is tombstoned"),
            Some(object) if object.kind == ObjectKind::RecordCard => (
                drift,
                "this object is already a record card; it names a record already",
            ),
            // A card cannot parent anything, so converting a frame that still
            // holds children would leave them pointing at a non-frame: the
            // scene would render them nested while no later batch could
            // re-parent them. Delete detaches children for exactly this
            // reason; promotion refuses instead, because dissolving someone's
            // grouping is not something they asked for.
            Some(object)
                if object.kind == ObjectKind::Frame
                    && frame_has_children(&mut tx, &canvas_id, &object.id).await? =>
            {
                (
                    "would_conflict",
                    "this frame still holds objects; a record card cannot parent them",
                )
            }
            // Nulling the connector's props would drop `semantic` while the
            // governed link it recorded stayed in place, with nothing on the
            // canvas naming it -- the same stranding assert_connector refuses.
            Some(object)
                if object.kind == ObjectKind::Connector
                    && object
                        .props
                        .get("semantic")
                        .and_then(Value::as_object)
                        .is_some_and(|semantic| {
                            semantic.get("status").and_then(Value::as_str) == Some("asserted")
                        }) =>
            {
                (
                    "would_conflict",
                    "this connector carries an asserted link; retract it before promoting",
                )
            }
            Some(object) => {
                let pinned = expected
                    .as_ref()
                    .and_then(|pins| pins.objects.get(&item.object_id));
                let drifted = pinned.is_some_and(|pins| {
                    version_moved(pins.geometry.as_deref(), object.geometry_seq)
                        || version_moved(pins.content.as_deref(), object.content_seq)
                });
                if canvas_stale || drifted {
                    (
                        "would_stale",
                        "this object has moved since the plan was made",
                    )
                } else {
                    ("would_accept", "")
                }
            }
        };
        if status != "would_accept" {
            all_accept = false;
        }
        let mut assessment = json!({
            "object_id": item.object_id,
            "status": status,
            "type": item.record_type,
            "kind": item.kind,
        });
        if !note.is_empty() {
            assessment["note"] = json!(note);
        }
        if let Some(object) = &loaded {
            assessment["versions"] = json!({
                "geometry": CanvasVersion(object.geometry_seq).encode(),
                "content": CanvasVersion(object.content_seq).encode(),
            });
            objects.push(object.clone());
        }
        assessments.push(assessment);
    }

    // Links are assessed too. A plan-required ceremony that previewed only
    // the records would let a person approve a promotion whose link names a
    // record they cannot write -- an approval spent on a plan guaranteed to
    // fail inside the transaction, after the records were already minted.
    let mut link_assessments: Vec<Value> = Vec::new();
    for link in &links {
        let from_planned = items.iter().any(|item| item.object_id == link.from);
        let to_planned = items.iter().any(|item| item.object_id == link.to);
        let (status, note) = if link.relationship.trim().is_empty() {
            ("would_conflict", "a link relationship must not be blank")
        } else if !from_planned
            && !can_record_in(&mut tx, &caller, &link.from, Capability::Edit).await?
        {
            (
                "would_conflict",
                "you may not edit the record this link starts from",
            )
        } else if !to_planned
            && !can_record_in(&mut tx, &caller, &link.to, Capability::View).await?
        {
            (
                "would_conflict",
                "you may not see the record this link points at",
            )
        } else {
            ("would_accept", "")
        };
        if status != "would_accept" {
            all_accept = false;
        }
        let mut assessment = json!({
            "from": link.from,
            "to": link.to,
            "relationship": link.relationship,
            "status": status,
            "from_promoted": from_planned,
            "to_promoted": to_planned,
        });
        if !note.is_empty() {
            assessment["note"] = json!(note);
        }
        link_assessments.push(assessment);
    }

    let digest = promotion_digest(&canvas_id, &reason, head, &objects, &items, &links);

    if dry_run {
        tx.rollback().await?;
        return Ok(json!({
            "action": "promote",
            "version": PROMOTE_VERSION,
            "outcome": "planned",
            "canvas_id": canvas_id,
            "canvas_version": head.encode(),
            "plan_digest": digest,
            "items": assessments,
            "links": link_assessments,
        }));
    }

    // Execution is bound to the plan. Both refusals are Error::Conflict rather
    // than a 200 outcome: the executor's plan runtime keys `plan_stale` off a
    // diagnostic containing "revision conflict", and a hosted caller needs the
    // 409 to tell a stale plan from a rejected one.
    let Some(supplied) = plan_digest else {
        tx.rollback().await?;
        return Err(Error::engine(
            "promote: executing a plan requires the plan_digest a dry run returned",
        ));
    };
    if supplied != digest || !all_accept {
        tx.rollback().await?;
        return Err(Error::conflict(format!(
            "promote: revision conflict; the canvas moved since the plan was made \
             (plan {supplied}, current {digest}). Prepare again."
        )));
    }

    // One reserved identity for every record, link, facet and the batch.
    let draft = crate::provenance::reserve_action_attestation()?;
    let caller_owner = super::mint::caller_owner_in(&mut tx, &caller, WRITE_TOOL).await?;
    let schema_rows = crate::query::cascade::schema_config_rows_in(&mut tx).await?;
    let canvas_home: Option<String> =
        sqlx::query_scalar("SELECT home_id FROM records WHERE id=? AND deleted_at IS NULL")
            .bind(&canvas_id)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();

    // Records first: an intra-cluster link cannot be written until both of its
    // endpoints exist, which is the whole reason promotion is composite.
    let mut minted: BTreeMap<String, String> = BTreeMap::new();
    for item in &items {
        let record_id = super::mint::mint_record_in(
            &db,
            &mut tx,
            &caller,
            &schema_rows,
            caller_owner.as_deref(),
            &reason,
            &super::mint::MintRequest {
                record_type: &item.record_type,
                kind: &item.kind,
                name: item.name.as_deref(),
                body: None,
                summary: item.summary.as_deref(),
                lifecycle: None,
                home_id: item.home_id.as_deref().or(canvas_home.as_deref()),
                facets: item.facets.as_ref(),
                links: &[],
            },
            &super::mint::MintPolicy {
                tool: WRITE_TOOL,
                refuse_message: true,
                refuse_supplied_member_of: false,
                // Promotion mints ordinary records, so a task or epic gets the
                // same default `create_record` would give it.
                workitem_lifecycle_default: true,
            },
            &draft,
        )
        .await?;
        minted.insert(item.object_id.clone(), record_id);
    }

    // The same required-facet guard `create_record` and `create_exploration`
    // apply. Without it promotion would be the one door through which a
    // record violating a required-facet rule could enter the store.
    let violations = super::lifecycle::required_violations_in(
        &mut tx,
        &schema_rows,
        &minted.values().map(String::as_str).collect::<Vec<_>>(),
    )
    .await?;
    super::lifecycle::assert_required_not_worsened(WRITE_TOOL, &Default::default(), &violations)?;

    // Links between promoted records, and from a promoted record to one that
    // already exists. An endpoint naming a promoted object resolves to its new
    // record; anything else must be a record the caller may already see.
    for link in &links {
        let resolve = |endpoint: &str| -> Option<String> { minted.get(endpoint).cloned() };
        let source = resolve(&link.from).unwrap_or_else(|| link.from.clone());
        let target = resolve(&link.to).unwrap_or_else(|| link.to.clone());
        if !minted.values().any(|id| id == &source) {
            require_record_in(&mut tx, &caller, WRITE_TOOL, &source, Capability::Edit).await?;
        }
        if !minted.values().any(|id| id == &target) {
            require_record_in(&mut tx, &caller, WRITE_TOOL, &target, Capability::View).await?;
        }
        write_link_in(
            &db,
            &mut tx,
            &caller,
            &source,
            &target,
            &link.relationship,
            link.note.clone(),
            &draft,
        )
        .await?;
    }

    // Every promoted record points back at the canvas it came from.
    for record_id in minted.values() {
        write_link_in(
            &db,
            &mut tx,
            &caller,
            record_id,
            &canvas_id,
            "derived_from",
            Some(format!("promoted from this canvas: {reason}")),
            &draft,
        )
        .await?;
    }

    // The batch converts each promoted object into a card in place. Nulling
    // every prop the object carried is what makes the merge a replacement:
    // a note's text must not survive onto a record card.
    let mut ops: Vec<Op> = Vec::new();
    let mut pre_images: BTreeMap<String, PreImage> = BTreeMap::new();
    for object in &objects {
        let record_id = minted
            .get(&object.id)
            .expect("every assessed object was minted");
        let mut patch = Map::new();
        let mut previous = Map::new();
        for key in object.props.keys() {
            patch.insert(key.clone(), Value::Null);
            previous.insert(key.clone(), object.props[key].clone());
        }
        patch.insert("record_id".into(), json!(record_id));
        patch.insert(
            "promoted_from".into(),
            json!({ "object_id": object.id, "attestation_id": draft.id() }),
        );
        previous.insert("record_id".into(), Value::Null);
        previous.insert("promoted_from".into(), Value::Null);
        ops.push(Op::Patch {
            id: object.id.clone(),
            expected: Expected {
                geometry: None,
                content: Some(CanvasVersion(object.content_seq).encode()),
            },
            set: PatchSet {
                props: Some(patch),
                kind: Some(ObjectKind::RecordCard),
                ..PatchSet::default()
            },
        });
        pre_images.insert(
            object.id.clone(),
            PreImage {
                geometry: object.geometry_seq,
                content: object.content_seq,
                props: Some(previous),
                ..PreImage::default()
            },
        );
    }
    let stored = StoredBatch {
        version: BATCH_VERSION.into(),
        batch_id: uuid::Uuid::new_v4().to_string(),
        base_version: Some(head.encode()),
        origin: canvas::Origin {
            kind: canvas::OriginKind::Promotion,
            gesture: None,
            undo_of: None,
            note: Some(reason.clone()),
        },
        ops: ops.clone(),
        ops_sha256: canvas::ops_digest(&ops)?,
        pre_images: pre_images.clone(),
        detached: Vec::new(),
    };
    let event = append_in(
        &db,
        &mut tx,
        AppendSpec {
            record_id: canvas_id.clone(),
            event_type: CANVAS_BATCH_EVENT_TYPE.into(),
            payload: serde_json::to_value(&stored)?,
            actor: Some(caller.actor().into()),
        },
    )
    .await?;

    // The facet is written after the batch precisely because it can name the
    // batch event, which the batch's own payload cannot.
    for (object_id, record_id) in &minted {
        let facet = crate::domain_transaction::FacetWrite {
            key: canvas::PROMOTED_FROM_FACET_KEY.into(),
            value: json!({
                "canvas_id": canvas_id,
                "object_id": object_id,
                "batch_event_id": event.id,
                "attestation_id": draft.id(),
            }),
            vocab_ref: None,
        };
        append_in(
            &db,
            &mut tx,
            crate::domain_transaction::facet_set_spec(record_id, &facet, caller.actor()),
        )
        .await?;
    }

    let objects_after = versions_after(event.local_seq, &ops, &pre_images, &[]);
    crate::provenance::issue_reserved_pending_action_in(&mut tx, draft).await?;
    db.commit_content(tx).await?;

    Ok(json!({
        "action": "promote",
        "version": PROMOTE_VERSION,
        "outcome": "committed",
        "canvas_id": canvas_id,
        "canvas_version": CanvasVersion(event.local_seq).encode(),
        "event_id": event.id,
        "batch_id": stored.batch_id,
        "plan_digest": digest,
        "promoted": minted
            .iter()
            .map(|(object_id, record_id)| json!({ "object_id": object_id, "record_id": record_id }))
            .collect::<Vec<_>>(),
        "objects": objects_after,
        "conflicts": [],
    }))
}

/// Does this frame still hold live children?
async fn frame_has_children(
    tx: &mut Transaction<'static, Sqlite>,
    canvas_id: &str,
    frame_id: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM canvas_objects
          WHERE canvas_id=? AND parent_id=? AND deleted=0)",
    )
    .bind(canvas_id)
    .bind(frame_id)
    .fetch_one(&mut **tx)
    .await?)
}

/// True when a pinned `canvas:N` token names a different version than the one
/// the object actually carries. An unparsable pin counts as drift.
fn version_moved(pinned: Option<&str>, current: i64) -> bool {
    match pinned {
        None => false,
        Some(token) => CanvasVersion::parse(token) != Some(CanvasVersion(current)),
    }
}

/// Bind a plan to exactly the state it was made against.
///
/// Covers the canvas version, every promoted object's two versions, and the
/// records and links the plan intends, so any drift in either the scene or the
/// request changes the digest and the execution is refused.
fn promotion_digest(
    canvas_id: &str,
    reason: &str,
    head: CanvasVersion,
    objects: &[SceneObject],
    items: &[PromoteItem],
    links: &[PromoteLink],
) -> String {
    let versions: Vec<Value> = objects
        .iter()
        .map(|object| {
            json!({
                "id": object.id,
                "geometry": CanvasVersion(object.geometry_seq).encode(),
                "content": CanvasVersion(object.content_seq).encode(),
            })
        })
        .collect();
    let planned: Vec<Value> = items
        .iter()
        .map(|item| {
            json!({
                "object_id": item.object_id,
                "type": item.record_type,
                "kind": item.kind,
                "name": item.name,
                "summary": item.summary,
                "home_id": item.home_id,
                "facets": item.facets,
            })
        })
        .collect();
    let planned_links: Vec<Value> = links
        .iter()
        .map(|link| {
            json!({
                "from": link.from,
                "to": link.to,
                "relationship": link.relationship,
                "note": link.note,
            })
        })
        .collect();
    crate::canonical_json::digest_json(&json!({
        "version": PROMOTE_VERSION,
        "canvas_id": canvas_id,
        // Bound because it is durable: the reason is written into every
        // minted record, into every derived_from link note, and into the
        // batch origin. Two different committed effects must not share a
        // digest.
        "reason": reason,
        "canvas_version": head.encode(),
        "objects": versions,
        "items": planned,
        "links": planned_links,
    }))
}

/// Write one link the way `manage_links.add` would, inside this transaction
/// and under the caller's reserved attestation.
#[allow(clippy::too_many_arguments)]
async fn write_link_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    source_id: &str,
    target_id: &str,
    relationship: &str,
    note: Option<String>,
    draft: &crate::provenance::ActionAttestationDraft,
) -> Result<()> {
    if relationship.trim().is_empty() {
        return Err(Error::engine(
            "manage_canvas.promote: a link relationship must not be blank",
        ));
    }
    // A comment's bearer is immutable, and `manage_links.add` refuses to move
    // one. Promotion writes links through the same governed path, so it owes
    // the same refusal.
    crate::comments::assert_bearer_immutable_on(
        tx,
        "manage_canvas.promote",
        source_id,
        relationship,
    )
    .await?;
    if super::links::relationship_owned_in(tx, source_id, target_id, relationship).await? {
        crate::relationship::legacy::mutate_from_canvas_in(
            tx,
            caller,
            source_id,
            target_id,
            relationship,
            note,
            draft,
        )
        .await?;
    } else {
        append_in(
            db,
            tx,
            AppendSpec {
                record_id: source_id.to_owned(),
                event_type: "link.added".into(),
                payload: serde_json::to_value(crate::events::LinkAddedPayload {
                    id: None,
                    source_id: source_id.to_owned(),
                    target_id: target_id.to_owned(),
                    relationship: relationship.to_owned(),
                    note,
                })?,
                actor: Some(caller.actor().into()),
            },
        )
        .await?;
    }
    Ok(())
}

/// What executor preparation returns for `canvas_write.manage_canvas.promote`.
pub(crate) struct PromotePreparation {
    pub canonical_source_arguments: Value,
    pub target_id: String,
    pub target: String,
    pub state_revision: String,
    pub target_state_digest: String,
    pub effect: Value,
    pub effect_summary: String,
    pub operation_evidence: Value,
}

/// Preparation for the plan-required promotion: the dry run, and nothing else.
///
/// This is the same code path the tools route uses, called with `dry_run:
/// true`, so preparation provably does not mutate: the handler rolls its
/// transaction back before returning a plan. The plan digest doubles as the
/// runtime's `target_state_digest`, which is what makes execution refuse any
/// drift in either the scene or the request.
pub(crate) async fn prepare_promote(
    db: &Db,
    caller: &Caller,
    arguments: Value,
) -> Result<PromotePreparation> {
    // Kept verbatim: the runtime re-prepares from these on execute and
    // compares the canonical arguments, so they must be the request rather
    // than anything derived from the plan.
    let mut canonical = arguments.clone();
    let ManageCanvasArgs::Promote {
        canvas_id,
        items,
        links,
        dry_run: _,
        expected,
        plan_digest: _,
        reason,
    } = parse_args(WRITE_TOOL, arguments)?
    else {
        return Err(Error::engine(
            "manage_canvas: executor preparation applies to the promote action",
        ));
    };

    let planned = promote(
        db.clone(),
        caller.clone(),
        canvas_id.clone(),
        items,
        links,
        true,
        expected,
        None,
        reason.clone(),
    )
    .await?;

    // A refusal at preparation time is an error, not a plan: handing back a
    // plan that is already known to fail would make the ceremony a formality.
    if planned.get("outcome").and_then(Value::as_str) != Some("planned") {
        let message = planned
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("promotion cannot be planned");
        return Err(Error::engine(format!("manage_canvas.promote: {message}")));
    }
    let assessments = planned
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let planned_links = planned
        .get("links")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if let Some(blocked) = assessments
        .iter()
        .chain(planned_links.iter())
        .find(|item| item.get("status").and_then(Value::as_str) != Some("would_accept"))
    {
        let status = blocked
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("would_conflict");
        let object = blocked
            .get("object_id")
            .and_then(Value::as_str)
            .or_else(|| blocked.get("from").and_then(Value::as_str))
            .unwrap_or_default();
        let note = blocked
            .get("note")
            .and_then(Value::as_str)
            .unwrap_or_default();
        // `would_stale` is drift, and the plan runtime keys `plan_stale` off
        // this phrase; `would_conflict` is a plan that was never coherent.
        return Err(if status == "would_stale" {
            Error::conflict(format!(
                "manage_canvas.promote: revision conflict; object {object} {note}"
            ))
        } else {
            Error::engine(format!(
                "manage_canvas.promote: object {object} cannot be promoted: {note}"
            ))
        });
    }

    let digest = planned
        .get("plan_digest")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let canvas_version = planned
        .get("canvas_version")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let name: Option<String> =
        sqlx::query_scalar("SELECT name FROM records WHERE id=? AND deleted_at IS NULL")
            .bind(&canvas_id)
            .fetch_optional(db.write_pool())
            .await?
            .flatten();
    let target = name.as_deref().map_or_else(
        || format!("canvas {canvas_id}"),
        |name| format!("{name} ({canvas_id})"),
    );
    let planned_records: Vec<Value> = assessments
        .iter()
        .map(|item| {
            json!({
                "object_id": item.get("object_id"),
                "type": item.get("type"),
                "kind": item.get("kind"),
            })
        })
        .collect();
    let count = planned_records.len();
    let effect = json!({
        "target": { "canvas_id": canvas_id, "name": name },
        "before": { "objects": count, "records": 0 },
        "after": { "record_cards": count, "records": count },
        "records": planned_records,
        // The whole link plan, not a count: a reviewer approving a promotion
        // needs to see that it will write onto records that already exist.
        "links": planned.get("links").cloned().unwrap_or(json!([])),
        "changed": true,
        "reason": reason,
    });
    canonical["dry_run"] = json!(false);
    canonical["plan_digest"] = json!(digest);

    Ok(PromotePreparation {
        canonical_source_arguments: canonical,
        target_id: canvas_id,
        target: target.clone(),
        state_revision: canvas_version,
        target_state_digest: digest,
        effect,
        effect_summary: format!(
            "promote {count} object{} on {target} into records, with provenance back to the canvas",
            if count == 1 { "" } else { "s" }
        ),
        operation_evidence: json!({ "items": assessments }),
    })
}

async fn is_live_canvas_pool(db: &Db, canvas_id: &str) -> Result<bool> {
    let mut snapshot = db.write_pool().begin().await?;
    let result = is_live_canvas(&mut snapshot, canvas_id).await;
    snapshot.rollback().await?;
    result
}

/// Register the two canvas tools. Two selector tools rather than one per
/// action: the hosted lens Complete profile has a few kilobytes of descriptor
/// headroom, and the batch grammar is documented in
/// `docs/canvas-protocol-v1.md` rather than inlined here for the same reason.
pub fn register_canvas_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::ReadCanvas,
        "Read a Document kind:canvas: the scene (get_scene), accepted batches after a \
         canvas:N version (changes), or a prose outline (describe). Cards resolve as the \
         caller; withheld records read \"withheld\". View required.",
        json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "enum": ["get_scene", "changes", "describe"] },
                "canvas_id": { "type": "string" },
                "include_deleted": { "type": "boolean", "description": "get_scene: with tombstones." },
                "after": { "type": "string", "description": "changes: after canvas:N." },
                "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 200 },
                "as_of": lens::as_of_input_schema()
            },
            "required": ["action", "canvas_id"],
            "additionalProperties": false
        }),
        read_canvas,
    )?;
    registry.register(
        ToolKind::ManageCanvas,
        "Write to a Document kind:canvas: commit one atomic native.canvas-batch.v1 \
         batch (commit_batch), make a connector between two record cards a governed \
         link (assert_connector), or turn canvas objects into governed records \
         (promote: plan-required, dry_run first). Edit on the canvas. Grammar and \
         outcomes: docs/canvas-protocol-v1.md.",
        json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "enum": ["commit_batch", "assert_connector", "promote"] },
                "batch": {
                    "type": "object",
                    "description": "commit_batch: the envelope."
                },
                "canvas_id": { "type": "string" },
                "object_id": { "type": "string", "description": "assert_connector: subject." },
                "relationship": { "type": "string", "description": "the link token." },
                "note": { "type": "string" },
                "items": { "type": "array", "items": { "type": "object" }, "description": "promote: what to mint." },
                "links": { "type": "array", "items": { "type": "object" }, "description": "promote: links; an endpoint may be a promoted object." },
                "dry_run": { "type": "boolean", "description": "promote: assess only." },
                "expected": { "type": "object", "description": "preconditions." },
                "plan_digest": { "type": "string", "description": "promote: from the dry run." },
                "reason": { "type": "string" }
            },
            "required": ["action"],
            "additionalProperties": false
        }),
        manage_canvas,
    )?;
    Ok(())
}
