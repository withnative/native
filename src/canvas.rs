//! Native Canvas v1 — the typed batch protocol and the scene fold.
//!
//! A canvas is an ordinary `Document kind:canvas` record whose scene is an
//! append-only stream of typed operation batches. Each accepted batch is ONE
//! `canvas.batch.committed.v1` content event on the canvas record's own
//! stream; the ordinary content projector folds it into `canvas_objects` (the
//! current scene, tombstones kept) and `canvas_batches` (the idempotency
//! ledger). Ops are never individual events.
//!
//! This module owns everything both the projector and the `manage_canvas` /
//! `read_canvas` tools must agree on: the wire shapes, the per-kind `props`
//! contract, the limits, and [`apply_batch`], the single fold. The tool layer
//! runs the same fold as a dry run inside a savepoint before it appends, so a
//! batch the projector would refuse is reported as a structured `rejected`
//! result instead of an engine error, and the projector re-validates every
//! referential rule so an imported or hand-written event can never project a
//! scene the tool would have refused.
//!
//! Two version groups per object — `geometry` (`x, y, w, h, z, parent`) and
//! `content` (`props`) — are each the `content_events.seq` of the batch that
//! last touched that group, encoded `canvas:N`. Compare-and-set on those
//! tokens is the tool layer's job; the fold only stamps them.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sqlx::{Row, SqliteConnection};

use crate::canonical_json::{canonical_json, digest_json};
use crate::error::{Error, Result};

/// The content event type one accepted batch becomes.
pub const CANVAS_BATCH_EVENT_TYPE: &str = "canvas.batch.committed.v1";
/// The batch envelope version clients submit.
pub const BATCH_VERSION: &str = "native.canvas-batch.v1";
/// The result envelope version `commit_batch` returns.
pub const RESULT_VERSION: &str = "native.canvas-batch-result.v1";

/// The version tag on a `manage_canvas.promote` plan or receipt.
pub const PROMOTE_VERSION: &str = "native.canvas-promotion.v1";
/// The `read_canvas.get_scene` envelope version.
pub const SCENE_VERSION: &str = "native.canvas-scene.v1";
/// The `read_canvas.changes` envelope version.
pub const CHANGES_VERSION: &str = "native.canvas-changes.v1";
/// The literal a withheld reference is replaced by on every read path.
pub const WITHHELD: &str = "withheld";

/// The engine-reserved facet promotion writes onto every record it mints.
///
/// Reserved rather than a pack-declared namespaced facet: a governed facet
/// any Edit holder could set through `create_record`/`update_record` would
/// let anyone forge canvas provenance. Only `manage_canvas.promote` writes
/// this, inside the promotion transaction, so its presence is evidence.
/// Value shape: `{canvas_id, object_id, batch_event_id, attestation_id}`.
pub const PROMOTED_FROM_FACET_KEY: &str = "canvas.promoted_from";

/// Limits, handler-enforced before `BEGIN` and re-checked by the fold.
pub const MAX_OPS_PER_BATCH: usize = 200;
pub const MAX_BATCH_CANONICAL_BYTES: usize = 256 * 1024;
pub const MAX_LIVE_OBJECTS: i64 = 5_000;
pub const MAX_NOTE_TEXT_BYTES: usize = 8 * 1024;
pub const MAX_STROKE_POINTS: usize = 2_000;
pub const MAX_ID_BYTES: usize = 128;
pub const MAX_Z_BYTES: usize = 128;
pub const MAX_ORIGIN_GESTURE_BYTES: usize = 64;
pub const MAX_ORIGIN_NOTE_BYTES: usize = 1024;

/// A `canvas:N` version token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CanvasVersion(pub i64);

impl CanvasVersion {
    pub fn encode(self) -> String {
        format!("canvas:{}", self.0)
    }

    pub fn parse(token: &str) -> Option<Self> {
        let digits = token.strip_prefix("canvas:")?;
        if digits.is_empty() || digits.len() > 18 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if digits.len() > 1 && digits.starts_with('0') {
            return None;
        }
        digits.parse().ok().map(Self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Note,
    Shape,
    Stroke,
    Connector,
    Frame,
    RecordCard,
}

impl ObjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Note => "note",
            Self::Shape => "shape",
            Self::Stroke => "stroke",
            Self::Connector => "connector",
            Self::Frame => "frame",
            Self::RecordCard => "record_card",
        }
    }

    pub fn parse(token: &str) -> Option<Self> {
        Some(match token {
            "note" => Self::Note,
            "shape" => Self::Shape,
            "stroke" => Self::Stroke,
            "connector" => Self::Connector,
            "frame" => Self::Frame,
            "record_card" => Self::RecordCard,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginKind {
    Gesture,
    Agent,
    Undo,
    Promotion,
    Assertion,
}

impl OriginKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gesture => "gesture",
            Self::Agent => "agent",
            Self::Undo => "undo",
            Self::Promotion => "promotion",
            Self::Assertion => "assertion",
        }
    }

    /// True for the origins only the engine may author.
    ///
    /// `assertion` and `promotion` batches are written by
    /// `manage_canvas.assert_connector` and `manage_canvas.promote` inside
    /// the engine's own transaction, and they are what licenses the
    /// governed props (`connector.semantic`, `record_card.promoted_from`).
    /// A client batch claiming one of these origins would therefore forge
    /// governed state, so [`validate_envelope`] refuses them at the client
    /// seam. The projector may trust the stored origin precisely because
    /// nothing else can have written it.
    pub fn is_engine_authored(self) -> bool {
        matches!(self, Self::Assertion | Self::Promotion)
    }
}

/// Who authored the props being validated.
///
/// The fold runs for both the tool and the projector, over both client and
/// engine batches, so the authority travels with the batch rather than being
/// inferred from the call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PropsAuthority {
    Client,
    Engine,
}

impl PropsAuthority {
    pub fn of(origin: OriginKind) -> Self {
        if origin.is_engine_authored() {
            Self::Engine
        } else {
            Self::Client
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    pub kind: OriginKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gesture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undo_of: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The batch envelope a client submits to `manage_canvas.commit_batch`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchEnvelope {
    pub version: String,
    pub canvas_id: String,
    pub batch_id: String,
    #[serde(default)]
    pub base_version: Option<String>,
    pub origin: Origin,
    pub ops: Vec<Op>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewObject {
    pub id: String,
    pub kind: ObjectKind,
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
    pub z: String,
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub props: Map<String, Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expected {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geometry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

/// The fields a `patch` may set. `parent` is a double option so that an
/// absent key (leave alone) and an explicit `null` (detach from its frame)
/// stay distinguishable on the wire.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchSet {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub w: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub z: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "double_option"
    )]
    pub parent: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub props: Option<Map<String, Value>>,
    /// Engine-only. Promotion converts an object into a `record_card` in
    /// place, so the object id is stable across the boundary; a client may
    /// not change an object's kind, and `validate_props` refuses this field
    /// under `PropsAuthority::Client`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<ObjectKind>,
}

impl PatchSet {
    pub fn touches_geometry(&self) -> bool {
        self.x.is_some()
            || self.y.is_some()
            || self.w.is_some()
            || self.h.is_some()
            || self.z.is_some()
            || self.parent.is_some()
    }

    pub fn touches_content(&self) -> bool {
        if self.kind.is_some() {
            return true;
        }
        self.props.is_some()
    }
}

mod double_option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        value: &Option<Option<String>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(inner) => inner.serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Option<String>>, D::Error> {
        Option::<String>::deserialize(deserializer).map(Some)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Op {
    Create {
        object: NewObject,
    },
    Patch {
        id: String,
        #[serde(default)]
        expected: Expected,
        set: PatchSet,
    },
    Delete {
        id: String,
        #[serde(default)]
        expected: Expected,
    },
    Restore {
        id: String,
        #[serde(default)]
        expected: Expected,
    },
}

impl Op {
    pub fn object_id(&self) -> &str {
        match self {
            Op::Create { object } => &object.id,
            Op::Patch { id, .. } | Op::Delete { id, .. } | Op::Restore { id, .. } => id,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Op::Create { .. } => "create",
            Op::Patch { .. } => "patch",
            Op::Delete { .. } => "delete",
            Op::Restore { .. } => "restore",
        }
    }
}

/// The versions an object carried BEFORE a batch touched it, plus the previous
/// values of every field the op changed. Carried on the event so `changes`
/// and undo can invert a batch op by op without replaying history.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreImage {
    pub geometry: i64,
    pub content: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub w: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub z: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "double_option"
    )]
    pub parent: Option<Option<String>>,
    /// Previous values of the patched `props` keys; a key that did not exist
    /// before is recorded as `null` so the inverse patch deletes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub props: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
}

/// The payload stored on `canvas.batch.committed.v1`. `ops` are the
/// normalised submitted ops (typed, so numbers are spelled identically on
/// every read path); `ops_sha256` is the JCS digest of that array, recomputed
/// by the projector so the ledger is rebuildable from the log alone.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredBatch {
    pub version: String,
    pub batch_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_version: Option<String>,
    pub origin: Origin,
    pub ops: Vec<Op>,
    pub ops_sha256: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pre_images: BTreeMap<String, PreImage>,
    /// Objects whose `parent` frame this batch deleted. The fold detaches
    /// them as a geometry change attributed to this batch, so their versions
    /// move without an op of their own; recording them here lets replay
    /// report exactly what the original commit reported.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detached: Vec<String>,
}

/// A child the fold detached because its parent frame was deleted, with the
/// versions it carried before the detach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detached {
    pub id: String,
    pub frame_id: String,
    pub geometry: i64,
    pub content: i64,
}

/// One row of `canvas_objects`.
#[derive(Clone, Debug, PartialEq)]
pub struct SceneObject {
    pub id: String,
    pub kind: ObjectKind,
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
    pub z: String,
    pub parent: Option<String>,
    pub props: Map<String, Value>,
    pub deleted: bool,
    pub geometry_seq: i64,
    pub content_seq: i64,
    pub created_seq: i64,
}

impl SceneObject {
    fn from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Self> {
        let kind: String = row.try_get("kind")?;
        let props: String = row.try_get("props")?;
        let props = match serde_json::from_str::<Value>(&props)? {
            Value::Object(map) => map,
            _ => return Err(Error::engine("canvas_objects.props is not an object")),
        };
        Ok(Self {
            id: row.try_get("object_id")?,
            kind: ObjectKind::parse(&kind)
                .ok_or_else(|| Error::engine(format!("unknown canvas object kind '{kind}'")))?,
            x: row.try_get("x")?,
            y: row.try_get("y")?,
            w: row.try_get("w")?,
            h: row.try_get("h")?,
            z: row.try_get("z")?,
            parent: row.try_get("parent_id")?,
            props,
            deleted: row.try_get::<i64, _>("deleted")? != 0,
            geometry_seq: row.try_get("geometry_seq")?,
            content_seq: row.try_get("content_seq")?,
            created_seq: row.try_get("created_seq")?,
        })
    }

    /// The wire shape of a scene object before redaction.
    pub fn to_value(&self) -> Value {
        json!({
            "id": self.id,
            "kind": self.kind.as_str(),
            "x": self.x, "y": self.y, "w": self.w, "h": self.h,
            "z": self.z,
            "parent": self.parent,
            "props": Value::Object(self.props.clone()),
            "versions": {
                "geometry": CanvasVersion(self.geometry_seq).encode(),
                "content": CanvasVersion(self.content_seq).encode(),
            },
            "deleted": self.deleted,
        })
    }
}

const SELECT_OBJECT: &str =
    "SELECT object_id,kind,x,y,w,h,z,parent_id,props,deleted,geometry_seq,content_seq,created_seq
   FROM canvas_objects WHERE canvas_id=? AND object_id=?";

pub async fn load_object(
    conn: &mut SqliteConnection,
    canvas_id: &str,
    object_id: &str,
) -> Result<Option<SceneObject>> {
    let row = sqlx::query(SELECT_OBJECT)
        .bind(canvas_id)
        .bind(object_id)
        .fetch_optional(&mut *conn)
        .await?;
    row.as_ref().map(SceneObject::from_row).transpose()
}

/// Every object on the canvas, live first by `z`, tombstones after.
pub async fn load_scene(
    conn: &mut SqliteConnection,
    canvas_id: &str,
    include_deleted: bool,
) -> Result<Vec<SceneObject>> {
    let rows = sqlx::query(
        "SELECT object_id,kind,x,y,w,h,z,parent_id,props,deleted,geometry_seq,content_seq,created_seq
           FROM canvas_objects WHERE canvas_id=? AND (deleted=0 OR ?)
          ORDER BY deleted, z, object_id",
    )
    .bind(canvas_id)
    .bind(include_deleted)
    .fetch_all(&mut *conn)
    .await?;
    rows.iter().map(SceneObject::from_row).collect()
}

/// The highest batch seq on the canvas, or 0 for a canvas nothing has
/// touched. Batch-only by design: the shell record's `rec:N` advances on
/// renames and links, which would make promotion plans falsely stale.
pub async fn current_version(
    conn: &mut SqliteConnection,
    canvas_id: &str,
) -> Result<CanvasVersion> {
    let seq: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(event_seq), 0) FROM canvas_batches WHERE canvas_id=?",
    )
    .bind(canvas_id)
    .fetch_one(&mut *conn)
    .await?;
    Ok(CanvasVersion(seq))
}

/// A refusal the fold can name. The tool layer turns it into a structured
/// `rejected` result; the projector turns it into an engine error that rolls
/// the append back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub object_id: Option<String>,
    pub message: String,
    pub limit: Option<&'static str>,
}

impl Refusal {
    fn new(code: &'static str, object_id: Option<&str>, message: impl Into<String>) -> Self {
        Self {
            code,
            object_id: object_id.map(str::to_owned),
            message: message.into(),
            limit: None,
        }
    }

    fn limit(name: &'static str, message: impl Into<String>) -> Self {
        Self {
            code: "limit_exceeded",
            object_id: None,
            message: message.into(),
            limit: Some(name),
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.object_id {
            Some(id) => write!(f, "{} ({}): {}", self.code, id, self.message),
            None => write!(f, "{}: {}", self.code, self.message),
        }
    }
}

/// Either a refusal the batch earned or an engine failure.
#[derive(Debug)]
pub enum FoldError {
    Refused(Refusal),
    Engine(Error),
}

impl From<Error> for FoldError {
    fn from(error: Error) -> Self {
        Self::Engine(error)
    }
}

impl From<sqlx::Error> for FoldError {
    fn from(error: sqlx::Error) -> Self {
        Self::Engine(error.into())
    }
}

impl From<serde_json::Error> for FoldError {
    fn from(error: serde_json::Error) -> Self {
        Self::Engine(error.into())
    }
}

impl From<FoldError> for Error {
    fn from(error: FoldError) -> Self {
        match error {
            FoldError::Refused(refusal) => {
                Error::engine(format!("canvas batch refused: {refusal}"))
            }
            FoldError::Engine(error) => error,
        }
    }
}

type FoldResult<T> = std::result::Result<T, FoldError>;

fn refuse<T>(
    code: &'static str,
    object_id: Option<&str>,
    message: impl Into<String>,
) -> FoldResult<T> {
    Err(FoldError::Refused(Refusal::new(code, object_id, message)))
}

fn finite(name: &str, value: f64, object_id: &str) -> FoldResult<()> {
    if value.is_finite() {
        Ok(())
    } else {
        refuse(
            "invalid_geometry",
            Some(object_id),
            format!("{name} must be a finite number"),
        )
    }
}

fn valid_token(name: &str, value: &str, max: usize, object_id: Option<&str>) -> FoldResult<()> {
    if value.is_empty() || value.len() > max || value.trim() != value {
        return refuse(
            "invalid_envelope",
            object_id,
            format!("{name} must be 1-{max} bytes of non-whitespace-padded text"),
        );
    }
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return refuse(
            "invalid_envelope",
            object_id,
            format!("{name} must not contain control characters"),
        );
    }
    Ok(())
}

/// Validate the envelope's structure and limits. Purely syntactic: nothing
/// here reads state. The tool runs it before `BEGIN`; the projector never
/// needs it because [`apply_batch`] re-checks every rule it cares about.
pub fn validate_envelope(envelope: &BatchEnvelope) -> FoldResult<()> {
    if envelope.version != BATCH_VERSION {
        return refuse(
            "invalid_envelope",
            None,
            format!("version must be {BATCH_VERSION}"),
        );
    }
    valid_token("canvas_id", &envelope.canvas_id, MAX_ID_BYTES, None)?;
    valid_token("batch_id", &envelope.batch_id, MAX_ID_BYTES, None)?;
    if let Some(base) = &envelope.base_version {
        if CanvasVersion::parse(base).is_none() {
            return refuse(
                "invalid_envelope",
                None,
                "base_version must be a canvas:N token",
            );
        }
    }
    if envelope.origin.kind.is_engine_authored() {
        return refuse(
            "invalid_envelope",
            None,
            format!(
                "origin.kind {} is written by the engine's own canvas actions, \
                 not submitted; commit_batch accepts gesture, agent or undo",
                envelope.origin.kind.as_str()
            ),
        );
    }
    if let Some(undo_of) = &envelope.origin.undo_of {
        valid_token("origin.undo_of", undo_of, MAX_ID_BYTES, None)?;
    }
    if let Some(gesture) = &envelope.origin.gesture {
        valid_token("origin.gesture", gesture, MAX_ORIGIN_GESTURE_BYTES, None)?;
    }
    if envelope
        .origin
        .note
        .as_ref()
        .is_some_and(|note| note.len() > MAX_ORIGIN_NOTE_BYTES)
    {
        return refuse(
            "invalid_envelope",
            None,
            format!("origin.note is at most {MAX_ORIGIN_NOTE_BYTES} bytes"),
        );
    }
    if envelope.ops.is_empty() {
        return refuse("invalid_envelope", None, "a batch carries at least one op");
    }
    if envelope.ops.len() > MAX_OPS_PER_BATCH {
        return Err(FoldError::Refused(Refusal::limit(
            "ops_per_batch",
            format!(
                "a batch carries at most {MAX_OPS_PER_BATCH} ops; this one carries {}",
                envelope.ops.len()
            ),
        )));
    }
    let bytes = canonical_json(&serde_json::to_value(&envelope.ops)?).len();
    if bytes > MAX_BATCH_CANONICAL_BYTES {
        return Err(FoldError::Refused(Refusal::limit(
            "batch_bytes",
            format!(
                "a batch is at most {MAX_BATCH_CANONICAL_BYTES} canonical bytes; this one is {bytes}"
            ),
        )));
    }
    let mut seen = BTreeSet::new();
    for op in &envelope.ops {
        let id = op.object_id();
        valid_token("object id", id, MAX_ID_BYTES, Some(id))?;
        if !seen.insert(id.to_owned()) {
            return refuse(
                "duplicate_object",
                Some(id),
                "an object may be the subject of at most one op per batch",
            );
        }
        match op {
            Op::Create { object } => {
                finite("x", object.x, id)?;
                finite("y", object.y, id)?;
                finite("w", object.w, id)?;
                finite("h", object.h, id)?;
                valid_token("z", &object.z, MAX_Z_BYTES, Some(id))?;
                if let Some(parent) = &object.parent {
                    valid_token("parent", parent, MAX_ID_BYTES, Some(id))?;
                    if object.kind == ObjectKind::Frame {
                        return refuse(
                            "invalid_envelope",
                            Some(id),
                            "a frame cannot have a parent",
                        );
                    }
                }
                validate_props(object.kind, &object.props, id, PropsAuthority::Client)?;
            }
            Op::Patch { id, expected, set } => {
                if !set.touches_geometry() && !set.touches_content() {
                    return refuse("invalid_envelope", Some(id), "patch sets nothing");
                }
                if set.touches_geometry() && expected.geometry.is_none() {
                    return refuse(
                        "invalid_precondition",
                        Some(id),
                        "a patch that touches geometry must name expected.geometry",
                    );
                }
                if set.touches_content() && expected.content.is_none() {
                    return refuse(
                        "invalid_precondition",
                        Some(id),
                        "a patch that touches props must name expected.content",
                    );
                }
                validate_expected(expected, id)?;
                if let Some(x) = set.x {
                    finite("x", x, id)?;
                }
                if let Some(y) = set.y {
                    finite("y", y, id)?;
                }
                if let Some(w) = set.w {
                    finite("w", w, id)?;
                }
                if let Some(h) = set.h {
                    finite("h", h, id)?;
                }
                if let Some(z) = &set.z {
                    valid_token("z", z, MAX_Z_BYTES, Some(id))?;
                }
                if let Some(Some(parent)) = &set.parent {
                    valid_token("parent", parent, MAX_ID_BYTES, Some(id))?;
                }
                if let Some(props) = &set.props {
                    if props.is_empty() {
                        return refuse("invalid_envelope", Some(id), "props patch is empty");
                    }
                }
            }
            Op::Delete { id, expected } | Op::Restore { id, expected } => {
                if expected.geometry.is_none() || expected.content.is_none() {
                    return refuse(
                        "invalid_precondition",
                        Some(id),
                        format!(
                            "{} must name expected.geometry and expected.content",
                            op.name()
                        ),
                    );
                }
                validate_expected(expected, id)?;
            }
        }
    }
    Ok(())
}

fn validate_expected(expected: &Expected, id: &str) -> FoldResult<()> {
    for (group, token) in [
        ("geometry", &expected.geometry),
        ("content", &expected.content),
    ] {
        if let Some(token) = token {
            match CanvasVersion::parse(token) {
                Some(CanvasVersion(0)) => {
                    return refuse(
                        "invalid_precondition",
                        Some(id),
                        format!("expected.{group} canvas:0 is never an issued object version"),
                    )
                }
                Some(_) => {}
                None => {
                    return refuse(
                        "invalid_precondition",
                        Some(id),
                        format!("expected.{group} must be a canvas:N token"),
                    )
                }
            }
        }
    }
    Ok(())
}

fn string_prop<'a>(props: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    props.get(key).and_then(Value::as_str)
}

/// The per-kind `props` contract. Unknown keys are refused so that the wire
/// shape stays honest for the workbench and for agents alike.
pub fn validate_props(
    kind: ObjectKind,
    props: &Map<String, Value>,
    id: &str,
    authority: PropsAuthority,
) -> FoldResult<()> {
    let allowed: &[&str] = match kind {
        ObjectKind::Note => &["text", "color"],
        ObjectKind::Shape => &["shape", "label", "color"],
        ObjectKind::Stroke => &["points", "width", "color"],
        ObjectKind::Connector => &["from", "to", "label", "style", "semantic"],
        ObjectKind::Frame => &["title", "color"],
        ObjectKind::RecordCard => &["record_id", "promoted_from"],
    };
    for key in props.keys() {
        if !allowed.contains(&key.as_str()) {
            return refuse(
                "invalid_envelope",
                Some(id),
                format!("props.{key} is not a {} property", kind.as_str()),
            );
        }
    }
    let optional_string = |key: &str, max: usize| -> FoldResult<()> {
        match props.get(key) {
            None | Some(Value::Null) => Ok(()),
            Some(Value::String(text)) if text.len() <= max => Ok(()),
            Some(Value::String(_)) => refuse(
                "limit_exceeded",
                Some(id),
                format!("props.{key} is at most {max} bytes"),
            ),
            Some(_) => refuse(
                "invalid_envelope",
                Some(id),
                format!("props.{key} must be a string"),
            ),
        }
    };
    match kind {
        ObjectKind::Note => {
            match props.get("text") {
                Some(Value::String(text)) if text.len() > MAX_NOTE_TEXT_BYTES => {
                    return Err(FoldError::Refused(Refusal {
                        code: "limit_exceeded",
                        object_id: Some(id.to_owned()),
                        message: format!("note text is at most {MAX_NOTE_TEXT_BYTES} bytes"),
                        limit: Some("note_text_bytes"),
                    }))
                }
                Some(Value::String(_)) | None | Some(Value::Null) => {}
                Some(_) => {
                    return refuse("invalid_envelope", Some(id), "props.text must be a string")
                }
            }
            optional_string("color", 64)?;
        }
        ObjectKind::Shape => {
            match string_prop(props, "shape") {
                Some("rect" | "ellipse") => {}
                _ => {
                    return refuse(
                        "invalid_envelope",
                        Some(id),
                        "props.shape must be \"rect\" or \"ellipse\"",
                    )
                }
            }
            optional_string("label", 1024)?;
            optional_string("color", 64)?;
        }
        ObjectKind::Stroke => {
            let Some(points) = props.get("points").and_then(Value::as_array) else {
                return refuse(
                    "invalid_envelope",
                    Some(id),
                    "props.points must be an array",
                );
            };
            if points.len() > MAX_STROKE_POINTS {
                return Err(FoldError::Refused(Refusal {
                    code: "limit_exceeded",
                    object_id: Some(id.to_owned()),
                    message: format!("a stroke carries at most {MAX_STROKE_POINTS} points"),
                    limit: Some("stroke_points"),
                }));
            }
            for point in points {
                let ok = point.as_array().is_some_and(|pair| {
                    pair.len() == 2 && pair.iter().all(|n| n.as_f64().is_some_and(f64::is_finite))
                });
                if !ok {
                    return refuse(
                        "invalid_envelope",
                        Some(id),
                        "props.points must be [dx, dy] pairs of finite numbers",
                    );
                }
            }
            if let Some(width) = props.get("width") {
                if !width.as_f64().is_some_and(|w| w.is_finite() && w > 0.0) {
                    return refuse(
                        "invalid_envelope",
                        Some(id),
                        "props.width must be a positive number",
                    );
                }
            }
            optional_string("color", 64)?;
        }
        ObjectKind::Connector => {
            for end in ["from", "to"] {
                let Some(endpoint) = props.get(end).and_then(Value::as_object) else {
                    return refuse(
                        "invalid_envelope",
                        Some(id),
                        format!("props.{end} must be an endpoint object"),
                    );
                };
                let anchored = endpoint.get("object").is_some_and(Value::is_string);
                let free = endpoint
                    .get("x")
                    .is_some_and(|v| v.as_f64().is_some_and(f64::is_finite))
                    && endpoint
                        .get("y")
                        .is_some_and(|v| v.as_f64().is_some_and(f64::is_finite));
                let keys_ok = endpoint
                    .keys()
                    .all(|key| matches!(key.as_str(), "object" | "side" | "x" | "y"));
                let side_ok = match endpoint.get("side") {
                    None | Some(Value::Null) => true,
                    Some(Value::String(side)) => {
                        matches!(side.as_str(), "top" | "right" | "bottom" | "left")
                    }
                    Some(_) => false,
                };
                if !keys_ok || !side_ok || anchored == free {
                    return refuse(
                        "invalid_envelope",
                        Some(id),
                        format!("props.{end} must be {{object, side?}} or {{x, y}}"),
                    );
                }
            }
            optional_string("label", 1024)?;
            match props.get("style") {
                None | Some(Value::Null) => {}
                Some(Value::String(style)) if matches!(style.as_str(), "line" | "arrow") => {}
                Some(_) => {
                    return refuse(
                        "invalid_envelope",
                        Some(id),
                        "props.style must be \"line\" or \"arrow\"",
                    )
                }
            }
            match props.get("semantic") {
                None | Some(Value::Null) => {}
                Some(_) if authority == PropsAuthority::Client => {
                    return refuse(
                        "invalid_envelope",
                        Some(id),
                        "semantic connectors are asserted through manage_canvas.assert_connector, not written directly",
                    )
                }
                Some(Value::Object(semantic)) => {
                    // Engine-authored, but still validated: the projector
                    // folds this on rebuild, so a malformed assertion must
                    // not be able to enter the log in the first place.
                    let keys_ok = semantic
                        .keys()
                        .all(|key| matches!(key.as_str(), "relationship" | "link_id" | "status"));
                    let relationship_ok = semantic
                        .get("relationship")
                        .and_then(Value::as_str)
                        .is_some_and(|token| !token.trim().is_empty() && token.len() <= MAX_ID_BYTES);
                    let link_ok = match semantic.get("link_id") {
                        None | Some(Value::Null) => true,
                        Some(Value::String(link)) => !link.is_empty() && link.len() <= MAX_ID_BYTES,
                        Some(_) => false,
                    };
                    // `broken` is deliberately absent: it is derived at read
                    // time from whether the link row still exists, never
                    // stored, because nothing hooks link removal (E3).
                    let status_ok = semantic
                        .get("status")
                        .and_then(Value::as_str)
                        .is_some_and(|status| matches!(status, "proposed" | "asserted"));
                    if !keys_ok || !relationship_ok || !link_ok || !status_ok {
                        return refuse(
                            "invalid_envelope",
                            Some(id),
                            "props.semantic must be {relationship, link_id?, status: proposed|asserted}",
                        );
                    }
                }
                Some(_) => {
                    return refuse(
                        "invalid_envelope",
                        Some(id),
                        "props.semantic must be an object",
                    )
                }
            }
        }
        ObjectKind::Frame => {
            optional_string("title", 1024)?;
            optional_string("color", 64)?;
        }
        ObjectKind::RecordCard => {
            match string_prop(props, "record_id") {
                Some(record_id)
                    if !record_id.trim().is_empty() && record_id.len() <= MAX_ID_BYTES => {}
                _ => {
                    return refuse(
                        "invalid_envelope",
                        Some(id),
                        "props.record_id must name a record",
                    )
                }
            }
            match props.get("promoted_from") {
                None | Some(Value::Null) => {}
                Some(_) if authority == PropsAuthority::Client => {
                    return refuse(
                        "invalid_envelope",
                        Some(id),
                        "props.promoted_from is written only by promotion",
                    )
                }
                Some(Value::Object(promoted)) => {
                    let shaped = promoted
                        .keys()
                        .all(|key| matches!(key.as_str(), "object_id" | "attestation_id"))
                        && ["object_id", "attestation_id"].iter().all(|key| {
                            promoted
                                .get(*key)
                                .and_then(Value::as_str)
                                .is_some_and(|value| {
                                    !value.trim().is_empty() && value.len() <= MAX_ID_BYTES
                                })
                        });
                    if !shaped {
                        return refuse(
                            "invalid_envelope",
                            Some(id),
                            "props.promoted_from must be {object_id, attestation_id}",
                        );
                    }
                }
                Some(_) => {
                    return refuse(
                        "invalid_envelope",
                        Some(id),
                        "props.promoted_from must be an object",
                    )
                }
            }
        }
    }
    Ok(())
}

/// One-level `props` merge: a `null` value deletes the key. Returns the
/// merged map and the pre-image of every patched key (`null` for a key that
/// did not exist, so the inverse patch deletes it again).
pub fn merge_props(
    current: &Map<String, Value>,
    patch: &Map<String, Value>,
) -> (Map<String, Value>, Map<String, Value>) {
    let mut merged = current.clone();
    let mut pre = Map::new();
    for (key, value) in patch {
        pre.insert(
            key.clone(),
            current.get(key).cloned().unwrap_or(Value::Null),
        );
        if value.is_null() {
            merged.remove(key);
        } else {
            merged.insert(key.clone(), value.clone());
        }
    }
    (merged, pre)
}

fn canonical_props_text(props: &Map<String, Value>) -> Result<String> {
    let bytes = canonical_json(&Value::Object(props.clone()));
    String::from_utf8(bytes).map_err(|_| Error::engine("canonical props are not UTF-8"))
}

async fn parent_is_live_frame(
    conn: &mut SqliteConnection,
    canvas_id: &str,
    parent: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM canvas_objects
          WHERE canvas_id=? AND object_id=? AND kind='frame' AND deleted=0)",
    )
    .bind(canvas_id)
    .bind(parent)
    .fetch_one(&mut *conn)
    .await?)
}

/// Fold one batch's forward ops into `canvas_objects` at `seq`, refusing on any
/// referential violation. Writes progressively: the caller owns the
/// transaction (or savepoint) that makes the fold atomic.
///
/// Compare-and-set on `expected` is deliberately NOT here: the projector must
/// accept every batch the tool accepted, and the tool has already compared.
pub async fn apply_batch(
    conn: &mut SqliteConnection,
    canvas_id: &str,
    seq: i64,
    ops: &[Op],
    authority: PropsAuthority,
) -> FoldResult<Vec<Detached>> {
    let mut detached = Vec::new();
    if ops.is_empty() || ops.len() > MAX_OPS_PER_BATCH {
        return Err(FoldError::Refused(Refusal::limit(
            "ops_per_batch",
            format!("a batch carries 1-{MAX_OPS_PER_BATCH} ops"),
        )));
    }
    let mut seen = BTreeSet::new();
    for op in ops {
        let id = op.object_id();
        if !seen.insert(id.to_owned()) {
            return refuse(
                "duplicate_object",
                Some(id),
                "an object may be the subject of at most one op per batch",
            );
        }
        match op {
            Op::Create { object } => {
                for (name, value) in [
                    ("x", object.x),
                    ("y", object.y),
                    ("w", object.w),
                    ("h", object.h),
                ] {
                    finite(name, value, id)?;
                }
                validate_props(object.kind, &object.props, id, authority)?;
                match load_object(conn, canvas_id, id).await? {
                    Some(existing) if existing.deleted => {
                        return refuse(
                            "object_deleted",
                            Some(id),
                            "this id names a tombstoned object; restore it instead",
                        )
                    }
                    Some(_) => {
                        return refuse("object_exists", Some(id), "this id is already in use")
                    }
                    None => {}
                }
                if let Some(parent) = &object.parent {
                    if object.kind == ObjectKind::Frame {
                        return refuse(
                            "invalid_envelope",
                            Some(id),
                            "a frame cannot have a parent",
                        );
                    }
                    if !parent_is_live_frame(conn, canvas_id, parent).await? {
                        return refuse(
                            "unknown_object",
                            Some(id),
                            format!("parent {parent} is not a live frame"),
                        );
                    }
                }
                sqlx::query(
                    "INSERT INTO canvas_objects
                       (canvas_id,object_id,kind,x,y,w,h,z,parent_id,props,deleted,
                        geometry_seq,content_seq,created_seq)
                     VALUES(?,?,?,?,?,?,?,?,?,?,0,?,?,?)",
                )
                .bind(canvas_id)
                .bind(id)
                .bind(object.kind.as_str())
                .bind(object.x)
                .bind(object.y)
                .bind(object.w)
                .bind(object.h)
                .bind(&object.z)
                .bind(&object.parent)
                .bind(canonical_props_text(&object.props)?)
                .bind(seq)
                .bind(seq)
                .bind(seq)
                .execute(&mut *conn)
                .await?;
            }
            Op::Patch { id, set, .. } => {
                let Some(current) = load_object(conn, canvas_id, id).await? else {
                    return refuse("unknown_object", Some(id), "no object with this id");
                };
                if current.deleted {
                    return refuse("object_deleted", Some(id), "the object is tombstoned");
                }
                if !set.touches_geometry() && !set.touches_content() {
                    return refuse("invalid_envelope", Some(id), "patch sets nothing");
                }
                let x = set.x.unwrap_or(current.x);
                let y = set.y.unwrap_or(current.y);
                let w = set.w.unwrap_or(current.w);
                let h = set.h.unwrap_or(current.h);
                for (name, value) in [("x", x), ("y", y), ("w", w), ("h", h)] {
                    finite(name, value, id)?;
                }
                let z = set.z.clone().unwrap_or_else(|| current.z.clone());
                let parent = match &set.parent {
                    Some(parent) => parent.clone(),
                    None => current.parent.clone(),
                };
                if let Some(parent) = &parent {
                    if current.kind == ObjectKind::Frame {
                        return refuse(
                            "invalid_envelope",
                            Some(id),
                            "a frame cannot have a parent",
                        );
                    }
                    if set.parent.is_some()
                        && !parent_is_live_frame(conn, canvas_id, parent).await?
                    {
                        return refuse(
                            "unknown_object",
                            Some(id),
                            format!("parent {parent} is not a live frame"),
                        );
                    }
                }
                // Promotion converts an object into a record card in place,
                // which is the one kind change the model admits and only for
                // an engine-authored batch. The object's id, geometry and z
                // are untouched, which is what "stable across the boundary"
                // means.
                let kind = match set.kind {
                    None => current.kind,
                    Some(_) if authority != PropsAuthority::Engine => {
                        return refuse(
                            "invalid_envelope",
                            Some(id),
                            "an object's kind is changed only by promotion",
                        )
                    }
                    Some(ObjectKind::RecordCard) if current.kind != ObjectKind::RecordCard => {
                        ObjectKind::RecordCard
                    }
                    Some(_) => {
                        return refuse(
                            "invalid_envelope",
                            Some(id),
                            "promotion converts an object into a record card and nothing else",
                        )
                    }
                };
                let props = match &set.props {
                    Some(patch) => {
                        // Refused even when the value is unchanged, so a
                        // record id can never travel in a patch op or a
                        // pre-image, where the change feed would have to
                        // redact it. A promotion patch is exempt: it is what
                        // gives the new card its record in the first place.
                        if current.kind == ObjectKind::RecordCard && patch.contains_key("record_id")
                        {
                            return refuse(
                                "invalid_envelope",
                                Some(id),
                                "a record card's record_id is immutable",
                            );
                        }
                        let (merged, _) = merge_props(&current.props, patch);
                        validate_props(kind, &merged, id, authority)?;
                        merged
                    }
                    None => current.props.clone(),
                };
                let geometry_seq = if set.touches_geometry() {
                    seq
                } else {
                    current.geometry_seq
                };
                let content_seq = if set.touches_content() {
                    seq
                } else {
                    current.content_seq
                };
                sqlx::query(
                    "UPDATE canvas_objects SET kind=?,x=?,y=?,w=?,h=?,z=?,parent_id=?,props=?,
                            geometry_seq=?,content_seq=?
                      WHERE canvas_id=? AND object_id=?",
                )
                .bind(kind.as_str())
                .bind(x)
                .bind(y)
                .bind(w)
                .bind(h)
                .bind(&z)
                .bind(&parent)
                .bind(canonical_props_text(&props)?)
                .bind(geometry_seq)
                .bind(content_seq)
                .bind(canvas_id)
                .bind(id)
                .execute(&mut *conn)
                .await?;
            }
            Op::Delete { id, .. } => {
                let Some(current) = load_object(conn, canvas_id, id).await? else {
                    return refuse("unknown_object", Some(id), "no object with this id");
                };
                if current.deleted {
                    return refuse(
                        "object_deleted",
                        Some(id),
                        "the object is already tombstoned",
                    );
                }
                sqlx::query(
                    "UPDATE canvas_objects SET deleted=1,geometry_seq=?,content_seq=?
                      WHERE canvas_id=? AND object_id=?",
                )
                .bind(seq)
                .bind(seq)
                .bind(canvas_id)
                .bind(id)
                .execute(&mut *conn)
                .await?;
                if current.kind == ObjectKind::Frame {
                    // Children detach in the same fold step, attributed to
                    // this batch as a geometry change.
                    let children = sqlx::query(
                        "SELECT object_id,geometry_seq,content_seq FROM canvas_objects
                          WHERE canvas_id=? AND parent_id=? AND deleted=0 ORDER BY object_id",
                    )
                    .bind(canvas_id)
                    .bind(id)
                    .fetch_all(&mut *conn)
                    .await?;
                    for child in children {
                        detached.push(Detached {
                            id: child.try_get("object_id")?,
                            frame_id: id.clone(),
                            geometry: child.try_get("geometry_seq")?,
                            content: child.try_get("content_seq")?,
                        });
                    }
                    sqlx::query(
                        "UPDATE canvas_objects SET parent_id=NULL,geometry_seq=?
                          WHERE canvas_id=? AND parent_id=? AND deleted=0",
                    )
                    .bind(seq)
                    .bind(canvas_id)
                    .bind(id)
                    .execute(&mut *conn)
                    .await?;
                }
            }
            Op::Restore { id, .. } => {
                let Some(current) = load_object(conn, canvas_id, id).await? else {
                    return refuse("unknown_object", Some(id), "no object with this id");
                };
                if !current.deleted {
                    return refuse("object_exists", Some(id), "the object is live");
                }
                // A parent frame that vanished while this object was
                // tombstoned no longer exists to it.
                let parent = match &current.parent {
                    Some(parent) if parent_is_live_frame(conn, canvas_id, parent).await? => {
                        Some(parent.clone())
                    }
                    _ => None,
                };
                sqlx::query(
                    "UPDATE canvas_objects SET deleted=0,parent_id=?,geometry_seq=?,content_seq=?
                      WHERE canvas_id=? AND object_id=?",
                )
                .bind(&parent)
                .bind(seq)
                .bind(seq)
                .bind(canvas_id)
                .bind(id)
                .execute(&mut *conn)
                .await?;
            }
        }
    }
    let live: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM canvas_objects WHERE canvas_id=? AND deleted=0")
            .bind(canvas_id)
            .fetch_one(&mut *conn)
            .await?;
    if live > MAX_LIVE_OBJECTS {
        return Err(FoldError::Refused(Refusal::limit(
            "live_objects",
            format!("a canvas holds at most {MAX_LIVE_OBJECTS} live objects; this batch would leave {live}"),
        )));
    }
    Ok(detached)
}

/// The digest the ledger stores: JCS over the normalised ops array.
pub fn ops_digest(ops: &[Op]) -> Result<String> {
    Ok(digest_json(&serde_json::to_value(ops)?))
}

/// Fold one `canvas.batch.committed.v1` event: ledger row, then the scene.
/// Called by the content projector on the event's own transaction.
pub(crate) async fn project_batch_committed(
    conn: &mut SqliteConnection,
    event: &crate::events::EventRow,
) -> Result<()> {
    let actor = event
        .actor
        .as_deref()
        .filter(|actor| !actor.trim().is_empty());
    if actor.is_none() {
        return Err(Error::engine(format!(
            "{CANVAS_BATCH_EVENT_TYPE} requires a non-empty actor"
        )));
    }
    let Some(payload) = event.payload.as_deref() else {
        return Err(Error::engine(format!(
            "{CANVAS_BATCH_EVENT_TYPE} has no payload"
        )));
    };
    let batch: StoredBatch = serde_json::from_str(payload)?;
    if batch.version != BATCH_VERSION {
        return Err(Error::engine(format!(
            "{CANVAS_BATCH_EVENT_TYPE} payload version must be {BATCH_VERSION}"
        )));
    }
    let shell = sqlx::query("SELECT type,kind,deleted_at FROM records WHERE id=?")
        .bind(&event.record_id)
        .fetch_optional(&mut *conn)
        .await?;
    let Some(shell) = shell else {
        return Err(Error::engine(format!(
            "cannot apply {CANVAS_BATCH_EVENT_TYPE}: record {} does not exist",
            event.record_id
        )));
    };
    if shell.try_get::<String, _>("type")? != "Document"
        || shell.try_get::<Option<String>, _>("kind")?.as_deref() != Some("canvas")
        || shell.try_get::<Option<String>, _>("deleted_at")?.is_some()
    {
        return Err(Error::engine(format!(
            "cannot apply {CANVAS_BATCH_EVENT_TYPE}: record {} is not a live Document kind:canvas",
            event.record_id
        )));
    }
    let digest = ops_digest(&batch.ops)?;
    if digest != batch.ops_sha256 {
        return Err(Error::engine(format!(
            "{CANVAS_BATCH_EVENT_TYPE} ops_sha256 does not match its ops"
        )));
    }
    let reused: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM canvas_batches WHERE canvas_id=? AND batch_id=?)",
    )
    .bind(&event.record_id)
    .bind(&batch.batch_id)
    .fetch_one(&mut *conn)
    .await?;
    if reused {
        return Err(Error::engine(format!(
            "{CANVAS_BATCH_EVENT_TYPE} reuses batch_id {} on canvas {}",
            batch.batch_id, event.record_id
        )));
    }
    sqlx::query(
        "INSERT INTO canvas_batches
           (canvas_id,batch_id,actor,event_id,event_seq,ops_sha256,origin_kind)
         VALUES(?,?,?,?,?,?,?)",
    )
    .bind(&event.record_id)
    .bind(&batch.batch_id)
    .bind(actor)
    .bind(&event.id)
    .bind(event.local_seq)
    .bind(&digest)
    .bind(batch.origin.kind.as_str())
    .execute(&mut *conn)
    .await?;
    apply_batch(
        conn,
        &event.record_id,
        event.local_seq,
        &batch.ops,
        PropsAuthority::of(batch.origin.kind),
    )
    .await?;
    // The stored `detached` list is a response-contract record, not fold
    // input: the fold recomputes it from state, which is what replay needs.
    // Activity moves; the shell's `updated_at` (update_record's concurrency
    // token) deliberately does not, so a drag never conflicts a rename.
    sqlx::query(
        "UPDATE records SET last_activity_at = CASE
            WHEN last_activity_at IS NULL OR last_activity_at < ?1 THEN ?1
            ELSE last_activity_at END
          WHERE id = ?2",
    )
    .bind(&event.created_at)
    .bind(&event.record_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The lossy `get_history` face of a batch event: enough to see that a batch
/// landed and who committed it, never the ops. The full payload is reachable
/// only through `read_canvas.changes`, which redacts.
pub fn history_summary(event: &Value) -> Value {
    let payload = event.get("payload").unwrap_or(&Value::Null);
    if payload.get("see").is_some() {
        // Already summarised at the redaction seam.
        return payload.clone();
    }
    let seq = event
        .get("local_seq")
        .or_else(|| event.get("seq"))
        .and_then(Value::as_i64);
    summary_of(
        payload,
        event.get("actor").cloned(),
        event.get("created_at").cloned(),
        seq,
    )
}

fn summary_of(payload: &Value, actor: Option<Value>, at: Option<Value>, seq: Option<i64>) -> Value {
    let op_count = payload
        .get("ops")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    // The key is `batch`, not `batch_id`: the generic history redaction nulls
    // every `*_id` that is not a viewable record, and a batch is not one.
    let batch = payload
        .get("batch")
        .or_else(|| payload.get("batch_id"))
        .cloned()
        .unwrap_or(Value::Null);
    json!({
        "actor": actor.unwrap_or(Value::Null),
        "at": at.unwrap_or(Value::Null),
        "op_count": op_count,
        "origin": { "kind": payload.pointer("/origin/kind").cloned().unwrap_or(Value::Null) },
        "batch": batch,
        "canvas_version": seq.map(|seq| CanvasVersion(seq).encode()),
        "see": "read_canvas.changes",
    })
}

/// Replace a batch event's stored payload with its lossy history summary
/// before generic redaction walks it. Idempotent; a no-op for other types.
pub fn summarise_event_row(event: &mut crate::events::EventRow) {
    if event.event_type != CANVAS_BATCH_EVENT_TYPE {
        return;
    }
    let payload: Value = event
        .payload
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or(Value::Null);
    if payload.get("see").is_some() {
        return;
    }
    let summary = summary_of(
        &payload,
        event.actor.clone().map(Value::String),
        Some(Value::String(event.created_at.clone())),
        Some(event.local_seq),
    );
    event.payload = Some(summary.to_string());
}

/// The version tag on a `read_canvas.describe` response.
pub const DESCRIBE_VERSION: &str = "native.canvas-describe.v1";

/// World-pixel gap within which two objects are treated as one visual
/// cluster. A little wider than a default note, so a deliberate grouping
/// reads as one cluster while two separate piles stay separate.
pub const CLUSTER_GAP: f64 = 160.0;

fn coord(object: &Value, key: &str) -> f64 {
    object.get(key).and_then(Value::as_f64).unwrap_or(0.0)
}

fn object_id(object: &Value) -> &str {
    object.get("id").and_then(Value::as_str).unwrap_or("")
}

/// Collapse whitespace and clip on a char boundary, so a multi-byte note
/// can never panic the outline or smuggle layout into it.
fn clip(text: &str, max: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        return flat;
    }
    let head: String = flat.chars().take(max).collect();
    format!("{}…", head.trim_end())
}

/// A human phrase for one **already-redacted** object.
///
/// `describe` is built from the redacted scene rather than the stored one,
/// so a withheld card cannot be named here even by mistake: the name it
/// would print simply is not present in the input.
fn describe_label(object: &Value) -> String {
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("object");
    let props = object.get("props").and_then(Value::as_object);
    let prop_str = |key: &str| {
        props
            .and_then(|p| p.get(key))
            .and_then(Value::as_str)
            .filter(|text| !text.trim().is_empty())
    };
    match kind {
        "note" => match prop_str("text") {
            Some(text) => format!("note “{}”", clip(text, 60)),
            None => "an empty note".to_string(),
        },
        "shape" => {
            let shape = prop_str("shape").unwrap_or("shape");
            match prop_str("label") {
                Some(label) => format!("{shape} “{}”", clip(label, 60)),
                None => format!("an unlabelled {shape}"),
            }
        }
        "stroke" => "a freehand stroke".to_string(),
        "frame" => match prop_str("title") {
            Some(title) => format!("frame “{}”", clip(title, 60)),
            None => "an untitled frame".to_string(),
        },
        "record_card" => match object
            .get("record")
            .and_then(|record| record.get("name"))
            .and_then(Value::as_str)
        {
            Some(name) => format!("card for “{}”", clip(name, 60)),
            None => "a withheld card".to_string(),
        },
        "connector" => "a connector".to_string(),
        other => format!("a {other}"),
    }
}

/// True when a card is present but its record was withheld from this caller.
fn is_withheld_card(object: &Value) -> bool {
    object.get("kind").and_then(Value::as_str) == Some("record_card")
        && object.get("record").is_none()
}

fn connector_sentence(connector: &Value, labels: &BTreeMap<String, String>) -> String {
    let props = connector.get("props").and_then(Value::as_object);
    let endpoint = |key: &str| -> String {
        let Some(end) = props.and_then(|p| p.get(key)).and_then(Value::as_object) else {
            return "a point".to_string();
        };
        match end.get("object").and_then(Value::as_str) {
            Some(id) => labels
                .get(id)
                .cloned()
                .unwrap_or_else(|| "a deleted object".to_string()),
            None => "a free point".to_string(),
        }
    };
    let from = endpoint("from");
    let to = endpoint("to");
    match props
        .and_then(|p| p.get("semantic"))
        .and_then(Value::as_object)
    {
        Some(semantic) => {
            let relationship = semantic
                .get("relationship")
                .and_then(Value::as_str)
                .unwrap_or("relates_to");
            let status = semantic
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("proposed");
            format!("{from} —{relationship}→ {to} ({status})")
        }
        None => {
            let label = props
                .and_then(|p| p.get("label"))
                .and_then(Value::as_str)
                .filter(|text| !text.trim().is_empty());
            match label {
                Some(label) => format!("{from} → {to} (“{}”, decorative)", clip(label, 60)),
                None => format!("{from} → {to} (decorative)"),
            }
        }
    }
}

/// Edge-to-edge gap between two bounding boxes on both axes, zero when they
/// overlap on that axis.
fn boxes_near(a: &Value, b: &Value) -> bool {
    let gap = |lo_key: &str, size_key: &str| -> f64 {
        let (a_lo, a_hi) = (coord(a, lo_key), coord(a, lo_key) + coord(a, size_key));
        let (b_lo, b_hi) = (coord(b, lo_key), coord(b, lo_key) + coord(b, size_key));
        (b_lo - a_hi).max(a_lo - b_hi).max(0.0)
    };
    gap("x", "w") <= CLUSTER_GAP && gap("y", "h") <= CLUSTER_GAP
}

/// Single-linkage clustering by proximity. Deterministic: members arrive in
/// reading order and clusters are emitted in the reading order of their
/// first member.
fn cluster_by_proximity(objects: &[&Value]) -> Vec<Vec<usize>> {
    let mut assigned: Vec<Option<usize>> = vec![None; objects.len()];
    let mut clusters: Vec<Vec<usize>> = Vec::new();
    for seed in 0..objects.len() {
        if assigned[seed].is_some() {
            continue;
        }
        let index = clusters.len();
        let mut members = vec![seed];
        assigned[seed] = Some(index);
        let mut frontier = vec![seed];
        while let Some(current) = frontier.pop() {
            for candidate in 0..objects.len() {
                if assigned[candidate].is_some()
                    || !boxes_near(objects[current], objects[candidate])
                {
                    continue;
                }
                assigned[candidate] = Some(index);
                members.push(candidate);
                frontier.push(candidate);
            }
        }
        members.sort_unstable();
        clusters.push(members);
    }
    clusters
}

/// Reading order: top to bottom, then left to right, then by id so that two
/// objects at the same point still order deterministically.
fn reading_order(a: &&Value, b: &&Value) -> std::cmp::Ordering {
    coord(a, "y")
        .total_cmp(&coord(b, "y"))
        .then(coord(a, "x").total_cmp(&coord(b, "x")))
        .then(object_id(a).cmp(object_id(b)))
}

/// Build the prose outline an agent reads instead of rendering the canvas.
///
/// Input must be the redacted scene as the caller sees it (the same values
/// `get_scene` returns), which is what keeps invariant §0.4 structural here
/// rather than a rule this function has to remember field by field.
pub fn describe_scene(canvas_id: &str, version: CanvasVersion, objects: &[Value]) -> Value {
    let live: Vec<&Value> = objects
        .iter()
        .filter(|object| object.get("deleted") != Some(&Value::Bool(true)))
        .collect();

    let mut labels: BTreeMap<String, String> = BTreeMap::new();
    for object in &live {
        labels.insert(object_id(object).to_string(), describe_label(object));
    }

    let kind_of = |object: &Value| -> String {
        object
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("object")
            .to_string()
    };
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for object in &live {
        *counts.entry(kind_of(object)).or_default() += 1;
    }
    let withheld = live
        .iter()
        .filter(|object| is_withheld_card(object))
        .count();

    let mut frames: Vec<&Value> = live
        .iter()
        .copied()
        .filter(|object| kind_of(object) == "frame")
        .collect();
    frames.sort_by(reading_order);

    let mut connectors: Vec<&Value> = live
        .iter()
        .copied()
        .filter(|object| kind_of(object) == "connector")
        .collect();
    connectors.sort_by(reading_order);

    let parent_of = |object: &Value| -> Option<String> {
        object
            .get("parent")
            .and_then(Value::as_str)
            .map(str::to_owned)
    };

    let mut lines: Vec<String> = Vec::new();

    // Framed content first: a frame is an author's own grouping, and it
    // outranks any proximity we would infer.
    for frame in &frames {
        let id = object_id(frame);
        let mut children: Vec<&Value> = live
            .iter()
            .copied()
            .filter(|object| parent_of(object).as_deref() == Some(id))
            .collect();
        children.sort_by(reading_order);
        let label = describe_label(frame);
        if children.is_empty() {
            lines.push(format!("{label} is empty."));
        } else {
            let inner: Vec<String> = children.iter().map(|child| describe_label(child)).collect();
            lines.push(format!("{label} contains {}.", join_phrases(&inner)));
        }
    }

    // Everything else clusters by proximity.
    let loose: Vec<&Value> = live
        .iter()
        .copied()
        .filter(|object| {
            kind_of(object) != "frame"
                && kind_of(object) != "connector"
                && parent_of(object).is_none()
        })
        .collect();
    let mut ordered = loose.clone();
    ordered.sort_by(reading_order);
    let clusters = cluster_by_proximity(&ordered);
    for members in &clusters {
        let phrases: Vec<String> = members
            .iter()
            .map(|index| describe_label(ordered[*index]))
            .collect();
        let anchor = ordered[members[0]];
        let (x, y) = (coord(anchor, "x").round(), coord(anchor, "y").round());
        if phrases.len() == 1 {
            lines.push(format!("Near ({x}, {y}): {}.", phrases[0]));
        } else {
            lines.push(format!(
                "A group of {} near ({x}, {y}): {}.",
                phrases.len(),
                join_phrases(&phrases)
            ));
        }
    }

    for connector in &connectors {
        lines.push(format!("{}.", connector_sentence(connector, &labels)));
    }

    if withheld > 0 {
        lines.push(format!(
            "{withheld} card{} on this canvas point at records you cannot see; \
             they are placed but not named here.",
            if withheld == 1 { "" } else { "s" }
        ));
    }

    let headline = if live.is_empty() {
        "This canvas is empty.".to_string()
    } else {
        format!(
            "This canvas holds {} live object{}: {}.",
            live.len(),
            if live.len() == 1 { "" } else { "s" },
            join_phrases(
                &counts
                    .iter()
                    .map(|(kind, count)| format!("{count} {}", plural(kind, *count)))
                    .collect::<Vec<_>>()
            )
        )
    };

    let mut outline = headline;
    if !lines.is_empty() {
        outline.push_str("\n\n");
        outline.push_str(&lines.join("\n"));
    }

    json!({
        "action": "describe",
        "version": DESCRIBE_VERSION,
        "canvas_id": canvas_id,
        "canvas_version": version.encode(),
        "outline": outline,
        "live_objects": live.len(),
        "counts": counts,
        "withheld_cards": withheld,
        "frames": frames.len(),
        "clusters": clusters.len(),
        "connectors": connectors.len(),
    })
}

fn plural(kind: &str, count: usize) -> String {
    let word = match kind {
        "record_card" => "record card",
        other => other,
    };
    if count == 1 {
        word.to_string()
    } else {
        format!("{word}s")
    }
}

/// "a", "a and b", "a, b and c" — the outline is prose, so it reads as prose.
fn join_phrases(parts: &[String]) -> String {
    match parts {
        [] => String::new(),
        [only] => only.clone(),
        [head @ .., last] => format!("{} and {last}", head.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_tokens_round_trip_and_reject_noncanonical_spellings() {
        assert_eq!(CanvasVersion::parse("canvas:0"), Some(CanvasVersion(0)));
        assert_eq!(CanvasVersion::parse("canvas:17"), Some(CanvasVersion(17)));
        assert_eq!(CanvasVersion(17).encode(), "canvas:17");
        for bad in [
            "canvas:",
            "canvas:07",
            "rec:3",
            "17",
            "canvas:-1",
            "canvas: 3",
        ] {
            assert_eq!(CanvasVersion::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn patch_parent_distinguishes_absent_from_null() {
        let absent: PatchSet = serde_json::from_value(json!({ "x": 1.0 })).unwrap();
        assert_eq!(absent.parent, None);
        let detached: PatchSet = serde_json::from_value(json!({ "parent": null })).unwrap();
        assert_eq!(detached.parent, Some(None));
        let attached: PatchSet = serde_json::from_value(json!({ "parent": "frame-1" })).unwrap();
        assert_eq!(attached.parent, Some(Some("frame-1".into())));
        assert_eq!(
            serde_json::to_value(&detached).unwrap(),
            json!({ "parent": null })
        );
    }

    #[test]
    fn props_merge_deletes_on_null_and_records_pre_images() {
        let current: Map<String, Value> =
            serde_json::from_value(json!({ "text": "a", "color": "red" })).unwrap();
        let patch: Map<String, Value> =
            serde_json::from_value(json!({ "text": "b", "color": null, "extra": 1 })).unwrap();
        let (merged, pre) = merge_props(&current, &patch);
        assert_eq!(Value::Object(merged), json!({ "text": "b", "extra": 1 }));
        assert_eq!(
            Value::Object(pre),
            json!({ "text": "a", "color": "red", "extra": null })
        );
    }

    #[test]
    fn ops_digest_is_spelling_independent() {
        let client: Vec<Op> = serde_json::from_value(json!([
            { "op": "create", "object": { "id": "n1", "kind": "note", "x": 10, "y": 20, "w": 200, "h": 120, "z": "a0", "props": { "text": "hi" } } }
        ]))
        .unwrap();
        let spelled: Vec<Op> = serde_json::from_value(json!([
            { "op": "create", "object": { "id": "n1", "kind": "note", "x": 10.0, "y": 20.0, "w": 200.0, "h": 120.0, "z": "a0", "parent": null, "props": { "text": "hi" } } }
        ]))
        .unwrap();
        assert_eq!(ops_digest(&client).unwrap(), ops_digest(&spelled).unwrap());
    }

    #[test]
    fn envelope_validation_names_the_rule_it_refuses() {
        let envelope = |ops: Value| -> BatchEnvelope {
            serde_json::from_value(json!({
                "version": BATCH_VERSION,
                "canvas_id": "c1",
                "batch_id": "b1",
                "origin": { "kind": "gesture" },
                "ops": ops,
            }))
            .unwrap()
        };
        let twice = envelope(json!([
            { "op": "delete", "id": "n1", "expected": { "geometry": "canvas:1", "content": "canvas:1" } },
            { "op": "restore", "id": "n1", "expected": { "geometry": "canvas:1", "content": "canvas:1" } }
        ]));
        match validate_envelope(&twice) {
            Err(FoldError::Refused(refusal)) => assert_eq!(refusal.code, "duplicate_object"),
            other => panic!("{other:?}"),
        }
        let unpinned = envelope(json!([
            { "op": "patch", "id": "n1", "expected": {}, "set": { "x": 1 } }
        ]));
        match validate_envelope(&unpinned) {
            Err(FoldError::Refused(refusal)) => assert_eq!(refusal.code, "invalid_precondition"),
            other => panic!("{other:?}"),
        }
        let mut infinite = envelope(json!([
            { "op": "create", "object": { "id": "n1", "kind": "note", "x": 1, "y": 1, "w": 1, "h": 1, "z": "a" } }
        ]));
        if let Op::Create { object } = &mut infinite.ops[0] {
            object.h = f64::INFINITY;
        }
        assert!(matches!(
            validate_envelope(&infinite),
            Err(FoldError::Refused(Refusal {
                code: "invalid_geometry",
                ..
            }))
        ));
        let card = envelope(json!([
            { "op": "create", "object": { "id": "n1", "kind": "record_card", "x": 1, "y": 1, "w": 1, "h": 1, "z": "a", "props": { "record_id": "r1", "promoted_from": {} } } }
        ]));
        assert!(matches!(
            validate_envelope(&card),
            Err(FoldError::Refused(Refusal {
                code: "invalid_envelope",
                ..
            }))
        ));
    }
}
