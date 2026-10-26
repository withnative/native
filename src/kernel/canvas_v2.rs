//! Frozen v1 canvas custody activated into an independent native scene and ledger.
//! Public canvas positions retain the source batch sequence; native positions
//! are allocated above the host-attested frozen source frontier.
use super::*;
use serde_json::{json, Value};

pub(crate) const ACTIVATED: &str = "kernel.canvas_activated.v1";
pub(crate) const BATCH: &str = "kernel.canvas_batch_committed.v1";
const PREFIX: &str = "kernel:canvas:";
const JS_MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

pub(crate) const OBJECTS_DDL: &str = "CREATE TABLE canvas_objects (
 canvas_id TEXT NOT NULL, object_id TEXT NOT NULL, kind TEXT NOT NULL,
 x REAL NOT NULL,y REAL NOT NULL,w REAL NOT NULL,h REAL NOT NULL,
 z TEXT NOT NULL,parent_id TEXT,props TEXT NOT NULL CHECK(json_valid(props)),
 deleted INTEGER NOT NULL CHECK(deleted IN (0,1)),
 geometry_seq INTEGER NOT NULL CHECK(geometry_seq>0),
 content_seq INTEGER NOT NULL CHECK(content_seq>0),
 created_seq INTEGER NOT NULL CHECK(created_seq>0),
 PRIMARY KEY(canvas_id,object_id))";
pub(crate) const OBJECTS_INDEX: &str =
    "CREATE INDEX idx_kernel_canvas_objects_live ON canvas_objects(canvas_id,deleted,z)";
pub(crate) const BATCHES_DDL: &str = "CREATE TABLE canvas_batches (
 canvas_id TEXT NOT NULL,batch_id TEXT NOT NULL,actor TEXT,
 event_id TEXT NOT NULL UNIQUE,event_seq INTEGER NOT NULL UNIQUE CHECK(event_seq>0),
 ops_sha256 TEXT NOT NULL CHECK(length(ops_sha256)=64),origin_kind TEXT NOT NULL,
 PRIMARY KEY(canvas_id,batch_id))";
pub(crate) const SOURCES_DDL: &str = "CREATE TABLE kernel_canvas_source_events (
 event_id TEXT PRIMARY KEY,payload TEXT NOT NULL CHECK(json_valid(payload)),
 created_at TEXT NOT NULL,actor TEXT NOT NULL,source_actor TEXT NOT NULL)";
pub(crate) const ACTIVATIONS_DDL: &str = "CREATE TABLE kernel_canvas_activations (
 canvas_id TEXT PRIMARY KEY,origin TEXT NOT NULL,source_head TEXT NOT NULL CHECK(json_valid(source_head)),
 frozen_frontier INTEGER NOT NULL,capsule_seq INTEGER NOT NULL,event_seq INTEGER NOT NULL)";

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Activation {
    format: u32,
    canvas_id: String,
    source_head: Value,
    report_sha256: String,
    capsule_seq: i64,
}

/// Host-only proof: the source has been frozen, the complete canvas closure
/// verified, and importer write handles excluded from the serving generation.
#[derive(Clone)]
pub struct VerifiedFrozenCanvas(Activation);
impl VerifiedFrozenCanvas {
    /// # Safety
    /// The caller must attest the completed, frozen source import and exclude
    /// all importer write handles and credentials from the serving generation.
    /// No MCP caller or app data may construct this proof.
    pub unsafe fn from_verified_import_unchecked(
        canvas_id: String,
        source_head: Value,
        report_sha256: String,
        capsule_seq: i64,
    ) -> Self {
        Self(Activation {
            format: 1,
            canvas_id,
            source_head,
            report_sha256,
            capsule_seq,
        })
    }
}

fn invalid(message: impl AsRef<str>) -> Error {
    Error::engine(format!("native canvas activation: {}", message.as_ref()))
}
fn text<'a>(row: &'a Value, key: &str) -> Result<&'a str> {
    row[key]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid(format!("missing {key}")))
}
fn number(row: &Value, key: &str) -> Result<i64> {
    row[key]
        .as_i64()
        .ok_or_else(|| invalid(format!("invalid {key}")))
}
fn real_bits(row: &Value, key: &str) -> Result<u64> {
    let token = row[key]["native.v1.sqlite.real_bits"]
        .as_str()
        .ok_or_else(|| invalid(format!("missing {key} REAL bits")))?;
    if token.len() != 16 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid(format!("invalid {key} REAL bits")));
    }
    let bits =
        u64::from_str_radix(token, 16).map_err(|_| invalid(format!("invalid {key} REAL bits")))?;
    if !f64::from_bits(bits).is_finite() {
        return Err(invalid(format!("nonfinite {key}")));
    }
    Ok(bits)
}

pub(crate) async fn ensure_schema(conn: &mut SqliteConnection) -> Result<()> {
    for ddl in [OBJECTS_DDL, BATCHES_DDL, SOURCES_DDL, ACTIVATIONS_DDL] {
        sqlx::query(&ddl.replacen("CREATE TABLE", "CREATE TABLE IF NOT EXISTS", 1))
            .execute(&mut *conn)
            .await?;
    }
    sqlx::query(&OBJECTS_INDEX.replacen("CREATE INDEX", "CREATE INDEX IF NOT EXISTS", 1))
        .execute(&mut *conn)
        .await?;
    // An older target may have retained events but no projection tables.
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_canvas_activations")
        .fetch_one(&mut *conn)
        .await?;
    if count == 0 {
        let events =
            crate::conformance::rebuild::read_events_of_types(conn, &[ACTIVATED, BATCH]).await?;
        for event in &events {
            project(conn, event).await?;
        }
    }
    Ok(())
}

pub async fn activate_as(db: &Db, host: &str, proof: VerifiedFrozenCanvas) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    hq::require_import(&mut tx, host).await?;
    ensure_schema(&mut tx).await?;
    activate_on(db, &mut tx, host, &proof).await?;
    db.commit_kernel_content(tx).await?;
    Ok(())
}

pub(crate) async fn activate_on(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    host: &str,
    proof: &VerifiedFrozenCanvas,
) -> Result<()> {
    if inspect_frozen_activation_on(tx, proof).await? {
        return Ok(());
    }
    append_in(
        db,
        tx,
        AppendSpec {
            record_id: format!("{PREFIX}{}", proof.0.canvas_id),
            event_type: ACTIVATED.into(),
            payload: serde_json::to_value(&proof.0)?,
            actor: Some(host.into()),
        },
        &mut crate::act::ActAllocation::new(),
    )
    .await?;
    Ok(())
}

/// Read-only preflight shared with activation.
pub async fn inspect_frozen_activation_on(
    tx: &mut SqliteConnection,
    proof: &VerifiedFrozenCanvas,
) -> Result<bool> {
    let id = format!("{PREFIX}{}", proof.0.canvas_id);
    let prior: Option<String> = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE type=? AND record_id=? ORDER BY seq LIMIT 1",
    )
    .bind(ACTIVATED)
    .bind(&id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(prior) = prior {
        if serde_json::from_str::<Activation>(&prior)? != proof.0 {
            return Err(Error::conflict("native canvas activation evidence changed"));
        }
        return Ok(true);
    }
    verify(&mut *tx, &proof.0, i64::MAX).await?;
    Ok(false)
}

/// Every canvas shares one host-attested allocation floor, including boards
/// created after cutover. Native event sequences alone can overlap v1 tokens.
async fn clock_floor(conn: &mut SqliteConnection, before: i64) -> Result<i64> {
    let (low, high): (Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT min(frozen_frontier),max(frozen_frontier) FROM kernel_canvas_activations WHERE event_seq<?",
    ).bind(before).fetch_one(conn).await?;
    match (low, high) {
        (Some(low), Some(high)) if low == high => Ok(low),
        (None, None) => Err(invalid("canvas clock has not been activated")),
        _ => Err(invalid("canvas allocation floors disagree")),
    }
}

pub(crate) fn public_position(floor: i64, native_seq: i64) -> Result<i64> {
    floor
        .checked_add(native_seq)
        .filter(|position| native_seq > 0 && floor >= 0 && *position <= JS_MAX_SAFE_INTEGER)
        .ok_or_else(|| invalid("canvas clock exceeds the client exact-integer range"))
}

/// Empty native boards are readable after creation; imported boards require
/// their explicit frozen-scene activation. The first hosted roster is the
/// permanent boundary, regardless of later membership updates. Source import and
/// resume are refused after that boundary: a newly created Document/canvas has
/// no retained scene to activate. Require the native creation witness as well,
/// so a future host/import path cannot turn an imported scene into an empty one
/// merely by assigning it a post-roster created_seq.
pub(crate) async fn ready_on(
    conn: &mut SqliteConnection,
    id: &str,
    before: i64,
) -> Result<Option<i64>> {
    require_canvas_shell(conn, id).await?;
    let activated: Option<i64> = sqlx::query_scalar(
        "SELECT frozen_frontier FROM kernel_canvas_activations WHERE canvas_id=? AND event_seq<?",
    )
    .bind(id)
    .bind(before)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(floor) = activated {
        return Ok(Some(floor));
    }
    let created: Option<i64> =
        sqlx::query_scalar("SELECT created_seq FROM kernel_records WHERE id=?")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;
    let first: Option<i64> =
        sqlx::query_scalar("SELECT min(seq) FROM main.content_events WHERE type=? AND seq<?")
            .bind(hosted_identity::ROSTER_EVENT)
            .bind(before)
            .fetch_one(&mut *conn)
            .await?;
    match (created, first) {
        (Some(created), Some(first)) if created > first && created < before => {
            let native: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM main.content_events WHERE seq=? AND record_id=? AND type='kernel.record_created.v1')",
            )
            .bind(created)
            .bind(id)
            .fetch_one(&mut *conn)
            .await?;
            if !native {
                return Ok(None);
            }
            Ok(Some(clock_floor(conn, before).await?))
        }
        _ => Ok(None),
    }
}

pub(crate) enum PreparedBatch {
    Conflicts(Vec<crate::canvas::Conflict>),
    Ready(Box<crate::canvas::StoredBatch>),
}

/// Share validation, CAS, dry folding and exact undo evidence between the
/// sealed writer and replay. The dry fold never changes the authoritative scene.
pub(crate) async fn prepare_batch(
    conn: &mut SqliteConnection,
    envelope: &crate::canvas::BatchEnvelope,
    position: i64,
) -> std::result::Result<PreparedBatch, crate::canvas::FoldError> {
    use crate::canvas;
    canvas::validate_envelope(envelope)?;
    prepare_authorized_batch(conn, envelope, position, canvas::PropsAuthority::Client).await
}

/// Trusted promotion only. Public commit_batch still rejects engine origins.
pub(crate) async fn prepare_promotion(
    conn: &mut SqliteConnection,
    envelope: &crate::canvas::BatchEnvelope,
    position: i64,
) -> std::result::Result<PreparedBatch, crate::canvas::FoldError> {
    let mut shape = envelope.clone();
    shape.origin.kind = crate::canvas::OriginKind::Agent;
    crate::canvas::validate_envelope(&shape)?;
    prepare_authorized_batch(
        conn,
        envelope,
        position,
        crate::canvas::PropsAuthority::Engine,
    )
    .await
}

async fn prepare_authorized_batch(
    conn: &mut SqliteConnection,
    envelope: &crate::canvas::BatchEnvelope,
    position: i64,
    authority: crate::canvas::PropsAuthority,
) -> std::result::Result<PreparedBatch, crate::canvas::FoldError> {
    use crate::canvas::{self, PreImage};
    let (conflicts, mut pre_images) =
        canvas::compare_and_preimage(conn, &envelope.canvas_id, &envelope.ops).await?;
    if !conflicts.is_empty() {
        return Ok(PreparedBatch::Conflicts(conflicts));
    }
    sqlx::query("SAVEPOINT kernel_canvas_dry_fold")
        .execute(&mut *conn)
        .await?;
    let folded = canvas::apply_batch(
        conn,
        &envelope.canvas_id,
        position,
        &envelope.ops,
        authority,
    )
    .await;
    sqlx::query("ROLLBACK TO SAVEPOINT kernel_canvas_dry_fold")
        .execute(&mut *conn)
        .await?;
    sqlx::query("RELEASE SAVEPOINT kernel_canvas_dry_fold")
        .execute(&mut *conn)
        .await?;
    let detached = folded?;
    let op_ids = envelope
        .ops
        .iter()
        .map(|op| op.object_id())
        .collect::<std::collections::BTreeSet<_>>();
    let mut detached_ids = Vec::new();
    for child in detached {
        if !detached_ids.contains(&child.id) {
            detached_ids.push(child.id.clone());
        }
        if op_ids.contains(child.id.as_str()) || pre_images.contains_key(&child.id) {
            continue;
        }
        pre_images.insert(
            child.id,
            PreImage {
                geometry: child.geometry,
                content: child.content,
                parent: Some(Some(child.frame_id)),
                ..PreImage::default()
            },
        );
    }
    Ok(PreparedBatch::Ready(Box::new(canvas::StoredBatch {
        version: canvas::BATCH_VERSION.into(),
        batch_id: envelope.batch_id.clone(),
        base_version: envelope.base_version.clone(),
        origin: envelope.origin.clone(),
        ops: envelope.ops.clone(),
        ops_sha256: canvas::ops_digest(&envelope.ops)?,
        pre_images,
        detached: detached_ids,
    })))
}

pub(crate) async fn is_canvas_shell(conn: &mut SqliteConnection, id: &str) -> Result<bool> {
    if hq::tombstoned_on(conn, id).await? {
        return Ok(false);
    }
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records r WHERE r.id=?
        AND r.pin_family=? AND r.pin_version=1
        AND EXISTS(SELECT 1 FROM kernel_record_fields f WHERE f.record_id=r.id AND f.name='v1_type' AND f.value_json='\"Document\"')
        AND EXISTS(SELECT 1 FROM kernel_record_fields f WHERE f.record_id=r.id AND f.name='v1_kind' AND f.value_json='\"canvas\"'))")
        .bind(id).bind(crate::v2_standard::v1_compat::FAMILY).fetch_one(conn).await?)
}

async fn require_canvas_shell(conn: &mut SqliteConnection, id: &str) -> Result<()> {
    if !is_canvas_shell(conn, id).await? {
        return Err(invalid(
            "canvas carrier is not a live v1-compatible Document/canvas record",
        ));
    }
    Ok(())
}

async fn source_head(conn: &mut SqliteConnection, before: i64) -> Result<Value> {
    let raw:Option<String>=sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_source_head.v1' AND seq<? ORDER BY seq DESC LIMIT 1")
        .bind(before).fetch_optional(&mut *conn).await?;
    serde_json::from_str(&raw.ok_or_else(|| invalid("source head missing"))?).map_err(Into::into)
}

async fn verify(
    conn: &mut SqliteConnection,
    p: &Activation,
    before: i64,
) -> Result<(String, app_state::RetainedAppState)> {
    if p.format != 1
        || p.report_sha256.len() != 64
        || !p.report_sha256.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid("invalid frozen proof"));
    }
    let f = p.source_head["seq"]
        .as_i64()
        .ok_or_else(|| invalid("source frontier missing"))?;
    if !(0..JS_MAX_SAFE_INTEGER).contains(&f) {
        return Err(invalid("source frontier exceeds canvas clock"));
    }
    if source_head(conn, before).await? != p.source_head {
        return Err(invalid("frozen source head changed"));
    }
    let roster: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE type=? AND seq<?)")
            .bind(hosted_identity::ROSTER_EVENT)
            .bind(before)
            .fetch_one(&mut *conn)
            .await?;
    if !roster {
        return Err(invalid("hosted identity activation required"));
    }
    require_canvas_shell(conn, &p.canvas_id).await?;
    let (origin, state) = app_state::evidence_at(conn, &p.canvas_id, p.capsule_seq, before).await?;
    let custody = state
        .custody
        .as_ref()
        .ok_or_else(|| invalid("capsule frontier missing"))?;
    if state.source_deleted
        || p.source_head["origin"] != origin
        || custody.content_frontier != f
        || custody.control_frontier != p.source_head["control_seq"].as_i64().unwrap_or(-1)
        || !custody.missing_source_events.is_empty()
        || !custody.missing_control_events.is_empty()
    {
        return Err(invalid("incomplete or stale canvas custody"));
    }
    verify_ledger(&p.canvas_id, &state, f).await?;
    Ok((origin, state))
}

async fn verify_ledger(canvas_id: &str, state: &app_state::RetainedAppState, f: i64) -> Result<()> {
    let scratch = crate::db::open_database(":memory:").await?;
    let result = async {
        let mut conn = scratch.write_pool().acquire().await?;
        sqlx::query(OBJECTS_DDL).execute(&mut *conn).await?;
        let mut batches = state.canvas_batches.clone();
        batches.sort_by_key(|row| row["event_seq"].as_i64().unwrap_or(-1));
        let mut seen_ids = std::collections::BTreeSet::new();
        let mut prior = 0;
        for row in &batches {
            if row["canvas_id"] != canvas_id {
                return Err(invalid("batch bearer mismatch"));
            }
            let seq = number(row, "event_seq")?;
            if seq <= prior || seq > f {
                return Err(invalid(
                    "batch clock duplicate, out of order or beyond freeze",
                ));
            }
            prior = seq;
            if !seen_ids.insert(text(row, "batch_id")?.to_owned()) {
                return Err(invalid("duplicate batch id"));
            }
            let event = state
                .source_events
                .get(text(row, "event_id")?)
                .ok_or_else(|| invalid("batch source event missing"))?;
            if event["record_id"] != canvas_id
                || event["type"] != crate::canvas::CANVAS_BATCH_EVENT_TYPE
                || event["seq"] != seq
                || event["actor"] != row["actor"]
            {
                return Err(invalid("batch source event witness mismatch"));
            }
            let payload: crate::canvas::StoredBatch =
                serde_json::from_str(text(event, "payload")?)?;
            if payload.version != crate::canvas::BATCH_VERSION
                || payload.batch_id != row["batch_id"]
                || payload.origin.kind.as_str() != text(row, "origin_kind")?
                || payload.ops_sha256 != row["ops_sha256"]
                || crate::canvas::ops_digest(&payload.ops)? != payload.ops_sha256
            {
                return Err(invalid("batch payload witness mismatch"));
            }
            crate::canvas::apply_batch(
                &mut conn,
                canvas_id,
                seq,
                &payload.ops,
                crate::canvas::PropsAuthority::of(payload.origin.kind),
            )
            .await
            .map_err(|e| invalid(format!("batch ledger does not fold: {e:?}")))?;
        }
        let folded = crate::canvas::load_scene(&mut conn, canvas_id, true).await?;
        if folded.len() != state.canvas_objects.len() {
            return Err(invalid("batch ledger and scene object count differ"));
        }
        let by_id = state
            .canvas_objects
            .iter()
            .map(|row| text(row, "object_id").map(|id| (id.to_owned(), row)))
            .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
        if by_id.len() != state.canvas_objects.len() {
            return Err(invalid("duplicate object id"));
        }
        for object in folded {
            let row = by_id
                .get(&object.id)
                .ok_or_else(|| invalid("folded object missing from frozen scene"))?;
            if row["canvas_id"] != canvas_id
                || row["kind"] != object.kind.as_str()
                || real_bits(row, "x")? != object.x.to_bits()
                || real_bits(row, "y")? != object.y.to_bits()
                || real_bits(row, "w")? != object.w.to_bits()
                || real_bits(row, "h")? != object.h.to_bits()
                || row["z"] != object.z
                || row["parent_id"] != json!(object.parent)
                || row["props"]
                    != String::from_utf8(crate::canonical_json::canonical_json(&Value::Object(
                        object.props.clone(),
                    )))
                    .expect("canonical JSON is UTF-8")
                || number(row, "deleted")? != i64::from(object.deleted)
                || number(row, "geometry_seq")? != object.geometry_seq
                || number(row, "content_seq")? != object.content_seq
                || number(row, "created_seq")? != object.created_seq
            {
                return Err(invalid("frozen scene differs from replayed batch ledger"));
            }
        }
        Ok(())
    }
    .await;
    scratch.close().await;
    result
}

pub(crate) async fn project(
    conn: &mut SqliteConnection,
    event: &crate::events::EventRow,
) -> Result<()> {
    match event.event_type.as_str() {
        ACTIVATED => project_activation(conn, event).await,
        BATCH => project_batch(conn, event).await,
        _ => Err(invalid("unknown canvas event")),
    }
}

async fn project_activation(
    conn: &mut SqliteConnection,
    event: &crate::events::EventRow,
) -> Result<()> {
    let payload = event
        .payload
        .as_ref()
        .ok_or_else(|| invalid("activation payload missing"))?;
    let p: Activation = serde_json::from_str(payload)?;
    if event.record_id != format!("{PREFIX}{}", p.canvas_id) {
        return Err(invalid("activation aggregate mismatch"));
    }
    app_state::refuse_entity_collision(conn, &event.record_id).await?;
    let host = sqlx::query_scalar::<_, String>(
        "SELECT principal_id FROM kernel_principals WHERE auth_binding=?",
    )
    .bind(hq::HOST_IMPORT_BINDING)
    .fetch_one(&mut *conn)
    .await?;
    if event.actor.as_deref() != Some(&host) {
        return Err(invalid("activation actor is not the import host"));
    }
    let (origin, state) = verify(conn, &p, event.local_seq).await?;
    let f = p.source_head["seq"]
        .as_i64()
        .ok_or_else(|| invalid("frozen frontier missing"))?;
    let existing_floor: Option<i64> =
        sqlx::query_scalar("SELECT frozen_frontier FROM kernel_canvas_activations LIMIT 1")
            .fetch_optional(&mut *conn)
            .await?;
    if existing_floor.is_some_and(|floor| floor != f) {
        return Err(invalid("frozen canvas allocation floor changed"));
    }
    let changed=sqlx::query("INSERT INTO kernel_canvas_activations(canvas_id,origin,source_head,frozen_frontier,capsule_seq,event_seq) VALUES(?,?,?,?,?,?)")
        .bind(&p.canvas_id).bind(origin).bind(serde_json::to_string(&p.source_head)?).bind(f).bind(p.capsule_seq).bind(event.local_seq)
        .execute(&mut *conn).await?;
    if changed.rows_affected() != 1 {
        return Err(invalid("duplicate activation"));
    }
    for row in &state.canvas_objects {
        sqlx::query("INSERT INTO canvas_objects(canvas_id,object_id,kind,x,y,w,h,z,parent_id,props,deleted,geometry_seq,content_seq,created_seq) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(&p.canvas_id).bind(text(row,"object_id")?).bind(text(row,"kind")?)
            .bind(f64::from_bits(real_bits(row,"x")?)).bind(f64::from_bits(real_bits(row,"y")?))
            .bind(f64::from_bits(real_bits(row,"w")?)).bind(f64::from_bits(real_bits(row,"h")?))
            .bind(text(row,"z")?).bind(row["parent_id"].as_str()).bind(text(row,"props")?)
            .bind(number(row,"deleted")?).bind(number(row,"geometry_seq")?).bind(number(row,"content_seq")?).bind(number(row,"created_seq")?)
            .execute(&mut *conn).await?;
    }
    for row in &state.canvas_batches {
        let source_actor = text(row, "actor")?;
        let principal: Option<String> = sqlx::query_scalar(
            "SELECT principal_id FROM kernel_principals WHERE auth_binding=? AND kind='account'",
        )
        .bind(source_actor)
        .fetch_optional(&mut *conn)
        .await?;
        let principal = principal.ok_or_else(|| invalid("batch actor identity is unmapped"))?;
        let source = state
            .source_events
            .get(text(row, "event_id")?)
            .ok_or_else(|| invalid("batch event missing"))?;
        sqlx::query("INSERT INTO kernel_canvas_source_events(event_id,payload,created_at,actor,source_actor) VALUES(?,?,?,?,?)")
            .bind(text(row,"event_id")?).bind(text(source,"payload")?).bind(text(source,"created_at")?)
            .bind(&principal).bind(source_actor).execute(&mut *conn).await?;
        sqlx::query("INSERT INTO canvas_batches(canvas_id,batch_id,actor,event_id,event_seq,ops_sha256,origin_kind) VALUES(?,?,?,?,?,?,?)")
            .bind(&p.canvas_id).bind(text(row,"batch_id")?).bind(&principal)
            .bind(text(row,"event_id")?).bind(number(row,"event_seq")?)
            .bind(text(row,"ops_sha256")?).bind(text(row,"origin_kind")?)
            .execute(&mut *conn).await?;
    }
    Ok(())
}

async fn project_batch(conn: &mut SqliteConnection, event: &crate::events::EventRow) -> Result<()> {
    use crate::canvas::{self, BatchEnvelope, StoredBatch};
    let actor = event
        .actor
        .as_deref()
        .ok_or_else(|| invalid("batch actor missing"))?;
    if event.act.is_none()
        || !hosted_identity::account_admitted_before(conn, actor, event.local_seq).await?
    {
        return Err(invalid("batch requires an admitted account and act"));
    }
    let floor = ready_on(conn, &event.record_id, event.local_seq)
        .await?
        .ok_or_else(|| invalid("canvas has not been activated"))?;
    let position = public_position(floor, event.local_seq)?;
    let stored: StoredBatch = serde_json::from_str(
        event
            .payload
            .as_deref()
            .ok_or_else(|| invalid("batch payload missing"))?,
    )?;
    let reused: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM canvas_batches WHERE canvas_id=? AND batch_id=?)",
    )
    .bind(&event.record_id)
    .bind(&stored.batch_id)
    .fetch_one(&mut *conn)
    .await?;
    if reused {
        return Err(invalid("native batch reuses an accepted batch identity"));
    }
    let envelope = BatchEnvelope {
        version: stored.version.clone(),
        canvas_id: event.record_id.clone(),
        batch_id: stored.batch_id.clone(),
        base_version: stored.base_version.clone(),
        origin: stored.origin.clone(),
        ops: stored.ops.clone(),
    };
    let promotion = stored.origin.kind == canvas::OriginKind::Promotion;
    let prepared = if promotion {
        verify_promotion_witness(conn, event, &stored).await?;
        prepare_promotion(conn, &envelope, position).await?
    } else {
        prepare_batch(conn, &envelope, position).await?
    };
    let authority = if promotion {
        canvas::PropsAuthority::Engine
    } else {
        canvas::PropsAuthority::Client
    };
    let expected = match prepared {
        PreparedBatch::Ready(expected) => expected,
        PreparedBatch::Conflicts(conflicts) => {
            return Err(invalid(format!(
                "{} batch preconditions disagree with the preceding scene",
                conflicts.len()
            )))
        }
    };
    if serde_json::to_value(expected)? != serde_json::to_value(&stored)? {
        return Err(invalid(
            "batch undo evidence differs from the preceding scene",
        ));
    }
    // A native board's first batch retains the same shared floor as every
    // activated imported board. No synthetic batch is added to its feed.
    let created: i64 = sqlx::query_scalar("SELECT created_seq FROM kernel_records WHERE id=?")
        .bind(&event.record_id)
        .fetch_one(&mut *conn)
        .await?;
    sqlx::query("INSERT OR IGNORE INTO kernel_canvas_activations(canvas_id,origin,source_head,frozen_frontier,capsule_seq,event_seq) VALUES(?,'native',?,?,0,?)")
        .bind(&event.record_id).bind(serde_json::to_string(&json!({"native_created_seq":created,"clock_frontier":floor}))?)
        .bind(floor).bind(event.local_seq).execute(&mut *conn).await?;
    sqlx::query("INSERT INTO canvas_batches(canvas_id,batch_id,actor,event_id,event_seq,ops_sha256,origin_kind) VALUES(?,?,?,?,?,?,?)")
        .bind(&event.record_id).bind(&stored.batch_id).bind(actor).bind(&event.id).bind(position)
        .bind(&stored.ops_sha256).bind(stored.origin.kind.as_str()).execute(&mut *conn).await?;
    canvas::apply_batch(conn, &event.record_id, position, &stored.ops, authority).await?;
    Ok(())
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
mod tests {
    use super::*;
    use crate::canvas::{NewObject, ObjectKind, Op, Origin, OriginKind, StoredBatch};

    #[test]
    fn native_canvas_positions_refuse_overflow_and_loss_of_client_precision() {
        assert_eq!(public_position(17, 23).unwrap(), 40);
        assert!(public_position(JS_MAX_SAFE_INTEGER, 1).is_err());
        assert!(public_position(i64::MAX, 1).is_err());
        assert!(public_position(-1, 1).is_err());
        assert!(public_position(0, 0).is_err());
    }

    #[tokio::test]
    async fn schema_only_kernel_retains_frozen_canvas_tables() {
        let db = open_database(":memory:").await.unwrap();
        apply_schema(&db).await.unwrap();
        let schema = |db: Db| async move {
            sqlx::query_as::<_, (String, String)>(
                "SELECT name,sql FROM sqlite_master WHERE type='table' AND name IN ('canvas_objects','canvas_batches') ORDER BY name"
            ).fetch_all(db.pool()).await.unwrap()
        };
        let frozen = schema(db.clone()).await;
        assert_eq!(frozen.len(), 2);
        apply_kernel_schema(&db).await.unwrap();
        assert_eq!(frozen, schema(db.clone()).await);
        db.close().await;
        let db = create_kernel_database(":memory:").await.unwrap();
        assert_eq!(frozen, schema(db.clone()).await);
        replay_all_projections(&db).await.unwrap();
        assert_eq!(frozen, schema(db.clone()).await);
        db.close().await;
        let (db, _) = create_v2_database(":memory:", "account", "Native", "native-canvas-schema")
            .await
            .unwrap();
        let native = schema(db.clone()).await;
        assert_eq!(native.len(), 2);
        assert_ne!(native, frozen);
        db.close().await;
    }

    #[tokio::test]
    async fn frozen_canvas_ledger_replays_exact_scene_and_rejects_real_bit_drift() {
        let ops = vec![Op::Create {
            object: NewObject {
                id: "obj".into(),
                kind: ObjectKind::Note,
                x: 0.125,
                y: 2.0,
                w: 100.0,
                h: 50.0,
                z: "a".into(),
                parent: None,
                props: serde_json::from_value(json!({"text":"hello"})).unwrap(),
            },
        }];
        let stored = StoredBatch {
            version: crate::canvas::BATCH_VERSION.into(),
            batch_id: "batch".into(),
            base_version: None,
            origin: Origin {
                kind: OriginKind::Agent,
                gesture: None,
                undo_of: None,
                note: None,
            },
            ops_sha256: crate::canvas::ops_digest(&ops).unwrap(),
            ops,
            pre_images: Default::default(),
            detached: Vec::new(),
        };
        let mut state = app_state::RetainedAppState::default();
        state.canvas_batches.push(
            json!({"canvas_id":"canvas","batch_id":"batch","event_id":"source-event","event_seq":7,
            "actor":"account-a","ops_sha256":stored.ops_sha256,"origin_kind":"agent"}),
        );
        state.source_events.insert(
            "source-event".into(),
            json!({"id":"source-event","record_id":"canvas",
            "seq":7,"type":crate::canvas::CANVAS_BATCH_EVENT_TYPE,"actor":"account-a",
            "payload":serde_json::to_string(&stored).unwrap(),"created_at":"2026-01-01T00:00:00Z"}),
        );
        let bits = |n: f64| json!({"native.v1.sqlite.real_bits":format!("{:016x}",n.to_bits())});
        state.canvas_objects.push(json!({"canvas_id":"canvas","object_id":"obj","kind":"note",
            "x":bits(0.125),"y":bits(2.0),"w":bits(100.0),"h":bits(50.0),"z":"a","parent_id":null,
            "props":"{\"text\":\"hello\"}","deleted":0,"geometry_seq":7,"content_seq":7,"created_seq":7}));
        verify_ledger("canvas", &state, 9).await.unwrap();
        state.canvas_objects[0]["x"] = bits(0.12500000000000003);
        assert!(verify_ledger("canvas", &state, 9).await.is_err());
        state.canvas_objects[0]["x"] = bits(0.125);
        state.source_events.clear();
        assert!(verify_ledger("canvas", &state, 9).await.is_err());
    }
}

/// Native promotion can only convert freshly minted records from this same
/// act. The self-naming batch event is its durable native attestation; source
/// history/custody cannot manufacture this witness after activation.
async fn verify_promotion_witness(
    conn: &mut SqliteConnection,
    event: &crate::events::EventRow,
    batch: &crate::canvas::StoredBatch,
) -> Result<()> {
    use crate::canvas::{self, ObjectKind, Op};
    if batch.ops.is_empty()
        || batch.ops.len() > 50
        || batch.base_version.as_deref()
            != Some(
                canvas::current_version(conn, &event.record_id)
                    .await?
                    .encode()
                    .as_str(),
            )
        || batch
            .origin
            .note
            .as_deref()
            .is_none_or(|s| s.trim().is_empty())
        || batch.origin.gesture.is_some()
        || batch.origin.undo_of.is_some()
    {
        return Err(invalid("invalid promotion batch"));
    }
    let mut records = std::collections::BTreeSet::new();
    for op in &batch.ops {
        let Op::Patch { id, expected, set } = op else {
            return Err(invalid("promotion must patch existing objects"));
        };
        let current = canvas::load_object(conn, &event.record_id, id)
            .await?
            .filter(|object| !object.deleted)
            .ok_or_else(|| invalid("promotion source object missing"))?;
        if current.kind == ObjectKind::Frame {
            let children: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM canvas_objects WHERE canvas_id=? AND parent_id=? AND deleted=0)")
                .bind(&event.record_id).bind(id).fetch_one(&mut *conn).await?;
            if children {
                return Err(invalid("promotion cannot strand frame children"));
            }
        }
        if current.kind == ObjectKind::Connector
            && current
                .props
                .get("semantic")
                .and_then(|value| value.get("status"))
                .and_then(Value::as_str)
                == Some("asserted")
        {
            return Err(invalid("promotion cannot strand an asserted connector"));
        }
        let props = set
            .props
            .as_ref()
            .ok_or_else(|| invalid("promotion props missing"))?;
        let record = props
            .get("record_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("promotion record missing"))?;
        if set.kind != Some(ObjectKind::RecordCard)
            || set.touches_geometry()
            || expected.content.is_none()
            || !records.insert(record)
            || props.get("promoted_from")
                != Some(&json!({"object_id":id,"attestation_id":event.id}))
        {
            return Err(invalid("invalid promotion conversion"));
        }
        let created: Option<(String,Option<String>,Option<i64>)> = sqlx::query_as(
            "SELECT payload,actor,act FROM content_events WHERE record_id=? AND type='kernel.record_created.v1' AND seq<?"
        ).bind(record).bind(event.local_seq).fetch_optional(&mut *conn).await?;
        let Some((payload, actor, act)) = created else {
            return Err(invalid("promotion record creation witness missing"));
        };
        let payload: Value = serde_json::from_str(&payload)?;
        if actor != event.actor
            || act != event.act
            || payload.pointer("/origin/canvas_id").and_then(Value::as_str)
                != Some(event.record_id.as_str())
            || payload.pointer("/origin/object_id").and_then(Value::as_str) != Some(id.as_str())
            || payload
                .pointer("/origin/promotion_event_id")
                .and_then(Value::as_str)
                != Some(event.id.as_str())
        {
            return Err(invalid("promotion record creation witness differs"));
        }
    }
    Ok(())
}
