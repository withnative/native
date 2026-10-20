//! Anchored comment targets on the v2 kernel (HQ cutover W3).
//!
//! Comment records themselves are ordinary compat-carrier records
//! (`Annotation`/`comment` in `v1_type`/`v1_kind`): body is the utterance,
//! `lifecycle` is the root thread state, `summary` the resolution prose, and
//! the thread is one `part_of` generic link per comment (root to its target
//! record, reply to its root). What the carrier cannot hold is the body
//! anchor: the exact passage a root quotes. That lives here, projected from
//! the event log like every other kernel table, so replay rebuilds it.
//!
//! Freshness and semantic units stay deferred: the anchor pins the target
//! body revision and hash it was taken against, but no relocated/stale
//! validation is computed.
use super::*;

/// Body-anchored comment targets, one row per anchored root.
pub(crate) const DDL: &str = "CREATE TABLE kernel_comment_anchors (
 annotation_id TEXT PRIMARY KEY REFERENCES kernel_records(id),
 target_record_id TEXT NOT NULL REFERENCES kernel_records(id),
 source_slot TEXT NOT NULL, selectors TEXT NOT NULL,
 body_revision INTEGER NOT NULL, body_revision_source TEXT NOT NULL,
 body_sha256 TEXT NOT NULL,
 purpose TEXT, created_at TEXT NOT NULL, actor TEXT,
 event_seq INTEGER NOT NULL)";
pub(crate) const TARGET_INDEX_DDL: &str =
    "CREATE INDEX idx_kernel_comment_anchors_target ON kernel_comment_anchors(target_record_id)";

/// Ordinary anchored-root write, admitted on the comment's transaction.
pub(crate) const ANCHOR_SET_EVENT: &str = "kernel.comment_anchor_set.v1";
/// Sealed import of a v1 `annotation_targets` row, with legacy provenance.
pub(crate) const ANCHOR_IMPORTED_EVENT: &str = "kernel.comment_anchor_imported.v1";

/// Anchor state carried by both the ordinary and the sealed event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorPayload {
    pub target_record_id: String,
    pub source_slot: String,
    pub selectors: serde_json::Value,
    pub body_revision: i64,
    pub body_revision_source: RevisionSource,
    pub body_sha256: String,
    pub purpose: Option<String>,
}

/// Sealed import envelope: legacy provenance rides the payload, never the
/// native actor/timestamp envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorImport {
    #[serde(flatten)]
    pub anchor: AnchorPayload,
    pub created_at: String,
    pub actor: Option<String>,
}

/// Projected anchor row: the comment, its target, and the pinned revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub struct CommentAnchor {
    pub annotation_id: String,
    pub target_record_id: String,
    pub source_slot: String,
    pub selectors: String,
    pub body_revision: i64,
    pub body_revision_source: String,
    pub body_sha256: String,
    pub purpose: Option<String>,
    pub created_at: String,
    pub actor: Option<String>,
    pub event_seq: i64,
}

impl CommentAnchor {
    #[cfg(feature = "v2-kernel-probe")]
    pub fn revision_source(&self) -> Result<RevisionSource> {
        RevisionSource::parse(&self.body_revision_source)
    }
}

/// Where a pinned body revision comes from: a native body-lane event
/// sequence, or the v1 source row's own revision. Recorded, never
/// re-derived, so a facet or link edit on the bearer cannot silently move
/// the pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionSource {
    NativeBody,
    V1SourceSeq,
}

impl RevisionSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            RevisionSource::NativeBody => "native_body",
            RevisionSource::V1SourceSeq => "v1_source_seq",
        }
    }

    #[cfg(feature = "v2-kernel-probe")]
    fn parse(text: &str) -> Result<RevisionSource> {
        match text {
            "native_body" => Ok(RevisionSource::NativeBody),
            "v1_source_seq" => Ok(RevisionSource::V1SourceSeq),
            _ => Err(Error::engine(
                "kernel comment anchor: unknown body revision source",
            )),
        }
    }
}
/// Outcome of a sealed anchor import; unchanged imports append no event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorImportOutcome {
    Created,
    Updated,
    Unchanged,
}
fn invalid(message: impl Into<String>) -> Error {
    Error::engine(format!("kernel comment anchor: {}", message.into()))
}

/// Shape check shared by admission, import, and the MCP layer: `body` slot,
/// 1..=4 selectors, exactly one nonblank `text_quote`, data positions with
/// ordered offsets, and fragments only paired with a data position (the v1
/// import shape). Whether the selectors hold against the stored body is a
/// separate check on the write transaction.
pub(crate) fn validate_anchor_shape(
    target_record_id: &str,
    source_slot: &str,
    selectors: &serde_json::Value,
) -> Result<()> {
    if target_record_id.trim().is_empty() {
        return Err(invalid("anchor target record must not be empty"));
    }
    if source_slot != "body" {
        return Err(invalid(
            "anchored comment root must target its bearer's body",
        ));
    }
    let selectors = selectors
        .as_array()
        .ok_or_else(|| invalid("anchor selectors must be an array"))?;
    if selectors.is_empty() || selectors.len() > 4 {
        return Err(invalid("anchor selectors must hold 1..=4 entries"));
    }
    let mut quotes = 0;
    let mut positions = 0;
    let mut fragments = 0;
    for selector in selectors {
        let object = selector
            .as_object()
            .ok_or_else(|| invalid("anchor selector must be an object"))?;
        match object.get("type").and_then(serde_json::Value::as_str) {
            Some("text_quote") => {
                quotes += 1;
                let exact = object.get("exact").and_then(serde_json::Value::as_str);
                if exact.is_none_or(|exact| exact.is_empty()) {
                    return Err(invalid("anchor text_quote requires a nonblank exact"));
                }
            }
            Some("data_position") => {
                positions += 1;
                let start = object.get("start").and_then(serde_json::Value::as_u64);
                let end = object.get("end").and_then(serde_json::Value::as_u64);
                match (start, end) {
                    (Some(start), Some(end)) if start < end => {}
                    _ => return Err(invalid("anchor data_position requires start < end")),
                }
            }
            Some("fragment") => {
                fragments += 1;
            }
            _ => {
                return Err(invalid(
                    "anchor holds exactly one text_quote with data positions or paired fragments",
                ))
            }
        }
    }
    if quotes != 1 {
        return Err(invalid(
            "anchor holds exactly one text_quote with data positions or paired fragments",
        ));
    }
    if fragments > 0 && positions == 0 {
        return Err(invalid(
            "anchor fragment selectors must pair with a data_position",
        ));
    }
    Ok(())
}
/// Native-write shape: the frame path admits no fragments, as v1. Imports
/// may carry v1 fragment selectors paired with a data position.
pub(crate) fn validate_native_anchor_shape(
    target_record_id: &str,
    source_slot: &str,
    selectors: &serde_json::Value,
) -> Result<()> {
    validate_anchor_shape(target_record_id, source_slot, selectors)?;
    let fragments = selectors
        .as_array()
        .map(|selectors| {
            selectors
                .iter()
                .filter(|selector| {
                    selector.get("type").and_then(serde_json::Value::as_str) == Some("fragment")
                })
                .count()
        })
        .unwrap_or(0);
    if fragments > 0 {
        return Err(invalid(
            "anchor holds exactly one text_quote and no fragment",
        ));
    }
    Ok(())
}
/// Whether shaped selectors hold against a stored body: the quote names
/// exactly one anchored segment — one verbatim occurrence, honouring an
/// optional prefix/suffix — and every data position names that segment at
/// UTF-8 character boundaries. An optional `selected_sha256` must match the
/// sliced bytes when present. Fragment selectors are stored verbatim for
/// import parity and never match-checked here.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) fn anchor_holds(body: &str, selectors: &serde_json::Value) -> Result<()> {
    let selectors = selectors
        .as_array()
        .ok_or_else(|| invalid("anchor selectors must be an array"))?;
    let quote = selectors
        .iter()
        .find(|selector| {
            selector.get("type").and_then(serde_json::Value::as_str) == Some("text_quote")
        })
        .ok_or_else(|| invalid("anchor holds exactly one text_quote"))?;
    let exact = quote
        .get("exact")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid("anchor text_quote requires a nonblank exact"))?;
    let prefix = quote
        .get("prefix")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let suffix = quote
        .get("suffix")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    // The quote must identify exactly one anchored segment: every verbatim
    // occurrence that honours the optional prefix/suffix counts, and the
    // anchor holds only when precisely one survives.
    let mut matches = Vec::new();
    let mut search_from = 0;
    while let Some(offset) = body.get(search_from..).and_then(|tail| tail.find(exact)) {
        let start = search_from + offset;
        let end = start + exact.len();
        let prefix_ok = start
            .checked_sub(prefix.len())
            .and_then(|from| body.get(from..start))
            .is_some_and(|got| got == prefix);
        let suffix_ok = body
            .get(end..end + suffix.len())
            .is_some_and(|got| got == suffix);
        if prefix_ok && suffix_ok {
            matches.push((start, end));
        }
        search_from = start + 1;
        if search_from >= body.len() {
            break;
        }
    }
    if matches.len() != 1 {
        return Err(invalid(
            "the passage anchor must identify exactly one anchored segment",
        ));
    }
    for selector in selectors {
        if selector.get("type").and_then(serde_json::Value::as_str) != Some("data_position") {
            continue;
        }
        let start = selector
            .get("start")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as usize;
        let end = selector
            .get("end")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as usize;
        if !body.is_char_boundary(start) || !body.is_char_boundary(end) {
            return Err(invalid("anchor data_position is not a UTF-8 boundary"));
        }
        // Positions name the one anchored segment, not just its bytes.
        if (start, end) != matches[0] || body.get(start..end) != Some(exact) {
            return Err(invalid("the passage anchor does not match the stored body"));
        }
        if let Some(expected) = selector
            .get("selected_sha256")
            .and_then(serde_json::Value::as_str)
        {
            if sha256_hex(exact) != expected {
                return Err(invalid("anchor selected_sha256 does not match the passage"));
            }
        }
    }
    Ok(())
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) fn sha256_hex(text: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(text.as_bytes()))
}
/// Field-pair half of the comment identity check: the caller already holds
/// the record row and proved the compat pin, so only the verbatim v1 pair
/// remains. Thread position and the anchor table key off this, never off a
/// free-text kind.
pub(crate) async fn is_comment_fields_on(conn: &mut SqliteConnection, id: &str) -> Result<bool> {
    let fields: Vec<(String, String)> = sqlx::query_as(
        "SELECT name, value_json FROM kernel_record_fields WHERE record_id = ? AND name IN ('v1_type','v1_kind')",
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await?;
    let field = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key == name)
            .and_then(|(_, value)| serde_json::from_str::<serde_json::Value>(value).ok())
            .and_then(|value| value.as_str().map(str::to_owned))
    };
    Ok(field("v1_type").as_deref() == Some("Annotation")
        && field("v1_kind").as_deref() == Some("comment"))
}

/// Whether a kernel record carries `Annotation`/`comment` in the compat
/// carrier. Thread position and the anchor table key off this, never off a
/// free-text kind.
pub(crate) async fn is_comment_on(conn: &mut SqliteConnection, id: &str) -> Result<bool> {
    let row: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT kind, pin_family FROM kernel_records WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((kind, family)) = row else {
        return Ok(false);
    };
    if kind.as_deref() != Some(crate::v2_standard::v1_compat::KIND)
        || family.as_deref() != Some(crate::v2_standard::v1_compat::FAMILY)
    {
        return Ok(false);
    }
    is_comment_fields_on(conn, id).await
}

/// The single active `part_of` bearer of a comment, if exactly one exists.
/// The MCP layer turns absence or multiplicity into the v1 bearer refusal.
pub(crate) async fn bearer_on(conn: &mut SqliteConnection, id: &str) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT target_id FROM kernel_generic_links
          WHERE source_id = ? AND relationship = 'part_of' AND active = 1
          ORDER BY target_id",
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await?)
}

/// Thread position of a comment: a reply bears on a comment, a root on any
/// other record. Replies never nest: a bearer that is itself a reply is a
/// shape refusal at the call site, not a third position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(feature = "v2-kernel-probe")]
pub(crate) enum Position {
    Root,
    Reply,
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn position_on(conn: &mut SqliteConnection, bearer_id: &str) -> Result<Position> {
    Ok(if is_comment_on(conn, bearer_id).await? {
        Position::Reply
    } else {
        Position::Root
    })
}

/// Direct thread children: comments bearing `part_of` on this record.
/// Roots page newest first, replies oldest first, matching the v1 reader.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn children_on(
    conn: &mut SqliteConnection,
    bearer_id: &str,
    position: Position,
) -> Result<Vec<String>> {
    let order = match position {
        Position::Root => "r.created_at DESC, r.id DESC",
        Position::Reply => "r.created_at ASC, r.id ASC",
    };
    // Roots page newest first; replies oldest first. Comment identity is the
    // compat carrier pin plus the verbatim v1 pair, never a bare kind token.
    Ok(sqlx::query_scalar(&format!(
        "SELECT l.source_id FROM kernel_generic_links l
           JOIN kernel_records r ON r.id = l.source_id
           JOIN kernel_record_fields t ON t.record_id = r.id AND t.name = 'v1_type'
           JOIN kernel_record_fields k ON k.record_id = r.id AND k.name = 'v1_kind'
          WHERE l.target_id = ? AND l.relationship = 'part_of' AND l.active = 1
            AND r.kind = ? AND r.pin_family = ?
            AND t.value_json = '\"Annotation\"' AND k.value_json = '\"comment\"'
          ORDER BY {order}"
    ))
    .bind(bearer_id)
    .bind(crate::v2_standard::v1_compat::KIND)
    .bind(crate::v2_standard::v1_compat::FAMILY)
    .fetch_all(&mut *conn)
    .await?)
}
async fn visible(conn: &mut SqliteConnection, principal: &str, record: &str) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id = ?)")
            .bind(record)
            .fetch_optional(&mut *conn)
            .await?
            .unwrap_or(false)
            && kernel_effective_capability_on(conn, principal, record)
                .await?
                .allows(Capability::View),
    )
}

pub(crate) async fn admit(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if !matches!(
        event.event_type.as_str(),
        ANCHOR_SET_EVENT | ANCHOR_IMPORTED_EVENT
    ) {
        return Ok(());
    }
    if event.event_type == ANCHOR_IMPORTED_EVENT {
        hq::require_import(conn, event.actor.as_deref().unwrap_or("")).await?;
        return Ok(());
    }
    hq::record_edit(
        conn,
        event.actor.as_deref().unwrap_or(""),
        &event.record_id,
        None,
    )
    .await?;
    if !is_comment_on(conn, &event.record_id).await? {
        return Err(Error::engine(
            "kernel comment anchor: anchored record is not an Annotation/comment",
        ));
    }
    let payload = event_payload::<AnchorPayload>(event)?;
    validate_native_anchor_shape(
        &payload.target_record_id,
        &payload.source_slot,
        &payload.selectors,
    )?;
    if !visible(
        conn,
        event.actor.as_deref().unwrap_or(""),
        &payload.target_record_id,
    )
    .await?
    {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    Ok(())
}

/// Ordinary anchored-root write on a transaction the caller holds. The
/// comment record and its `part_of` bearer link already exist; this only
/// pins the passage against the target's current body revision.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn set_anchor_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut crate::act::ActAllocation,
    principal: &str,
    annotation_id: &str,
    payload: AnchorPayload,
) -> Result<()> {
    validate_native_anchor_shape(
        &payload.target_record_id,
        &payload.source_slot,
        &payload.selectors,
    )?;
    // Gate on visibility before touching the body: a hidden target reads as
    // missing, and no error below may distinguish the two.
    if !visible(&mut *tx, principal, &payload.target_record_id).await? {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    let body: Option<String> =
        sqlx::query_scalar("SELECT body FROM kernel_record_bodies WHERE record_id = ?")
            .bind(&payload.target_record_id)
            .fetch_optional(&mut **tx)
            .await?;
    anchor_holds(body.as_deref().unwrap_or(""), &payload.selectors)?;
    append_in(
        db,
        tx,
        AppendSpec {
            record_id: annotation_id.into(),
            event_type: ANCHOR_SET_EVENT.into(),
            payload: serde_json::to_value(payload)?,
            actor: Some(principal.into()),
        },
        acts,
    )
    .await?;
    Ok(())
}
/// Sealed import of one v1 `annotation_targets` row. Endpoints must already
/// be imported; identical retries report `Unchanged` and append nothing, so
/// resume is idempotent. The legacy actor is namespaced on the way in.
pub(crate) async fn import_anchor_as(
    db: &Db,
    principal: &str,
    annotation_id: &str,
    imported: &AnchorImport,
) -> Result<AnchorImportOutcome> {
    import_anchor_snapshot_as(db, principal, annotation_id, imported, false).await
}
pub(crate) async fn resume_anchor_as(
    db: &Db,
    principal: &str,
    annotation_id: &str,
    imported: &AnchorImport,
) -> Result<AnchorImportOutcome> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_comment_anchors WHERE annotation_id=?)",
    )
    .bind(annotation_id)
    .fetch_one(db.pool())
    .await?;
    if !exists {
        return import_anchor_as(db, principal, annotation_id, imported).await;
    }
    import_anchor_snapshot_as(db, principal, annotation_id, imported, true).await
}
async fn import_anchor_snapshot_as(
    db: &Db,
    principal: &str,
    annotation_id: &str,
    imported: &AnchorImport,
    delta: bool,
) -> Result<AnchorImportOutcome> {
    validate_anchor_shape(
        &imported.anchor.target_record_id,
        &imported.anchor.source_slot,
        &imported.anchor.selectors,
    )?;
    let mut import = imported.clone();
    import.actor = import.actor.map(|actor| format!("v1:{actor}"));
    let mut tx = begin_write(db.write_pool()).await?;
    hq::require_import(&mut tx, principal).await?;
    hq::require_source_import_open(&mut tx).await?;
    let prior: Option<CommentAnchor> = sqlx::query_as(
        "SELECT annotation_id,target_record_id,source_slot,selectors,body_revision,body_revision_source,body_sha256,purpose,created_at,actor,event_seq FROM kernel_comment_anchors WHERE annotation_id = ?",
    )
    .bind(annotation_id)
    .fetch_optional(&mut *tx)
    .await?;
    let updating = prior.is_some();
    if let Some(prior) = prior {
        let same = prior.target_record_id == import.anchor.target_record_id
            && prior.source_slot == import.anchor.source_slot
            && prior.selectors
                == serde_json::to_string(&import.anchor.selectors).unwrap_or_default()
            && prior.body_revision == import.anchor.body_revision
            && prior.body_revision_source == import.anchor.body_revision_source.as_str()
            && prior.body_sha256 == import.anchor.body_sha256
            && prior.purpose == import.anchor.purpose
            && prior.created_at == import.created_at
            && prior.actor == import.actor;
        if same {
            tx.rollback().await?;
            return Ok(AnchorImportOutcome::Unchanged);
        }
        let owned: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM content_events WHERE seq=? AND type=? AND actor=?)",
        )
        .bind(prior.event_seq)
        .bind(ANCHOR_IMPORTED_EVENT)
        .bind(principal)
        .fetch_one(&mut *tx)
        .await?;
        if !delta || !owned {
            return Err(Error::conflict(
                "comment anchor import content differs or has native edits",
            ));
        }
    }
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: annotation_id.into(),
            event_type: ANCHOR_IMPORTED_EVENT.into(),
            payload: serde_json::to_value(import)?,
            actor: Some(principal.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(if updating {
        AnchorImportOutcome::Updated
    } else {
        AnchorImportOutcome::Created
    })
}

/// Fold either anchor event into the projection. Pure state replacement:
/// the event carries the full row, so replay rebuilds the table exactly.
pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let (anchor, created_at, actor) = if event.event_type == ANCHOR_IMPORTED_EVENT {
        hq::require_import(conn, event.actor.as_deref().unwrap_or("")).await?;
        let import = event_payload::<AnchorImport>(event)?;
        validate_anchor_shape(
            &import.anchor.target_record_id,
            &import.anchor.source_slot,
            &import.anchor.selectors,
        )?;
        (import.anchor, import.created_at, import.actor)
    } else if event.event_type == ANCHOR_SET_EVENT {
        let payload = event_payload::<AnchorPayload>(event)?;
        validate_native_anchor_shape(
            &payload.target_record_id,
            &payload.source_slot,
            &payload.selectors,
        )?;
        (payload, event.created_at.clone(), event.actor.clone())
    } else {
        return Err(Error::engine("unknown comment anchor event"));
    };
    sqlx::query(
        "INSERT INTO kernel_comment_anchors
           (annotation_id,target_record_id,source_slot,selectors,body_revision,body_revision_source,body_sha256,purpose,created_at,actor,event_seq)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)
         ON CONFLICT(annotation_id) DO UPDATE SET
           target_record_id = excluded.target_record_id, source_slot = excluded.source_slot,
           selectors = excluded.selectors, body_revision = excluded.body_revision,
           body_revision_source = excluded.body_revision_source,
           body_sha256 = excluded.body_sha256, purpose = excluded.purpose,
           created_at = excluded.created_at, actor = excluded.actor,
           event_seq = excluded.event_seq",
    )
    .bind(&event.record_id)
    .bind(&anchor.target_record_id)
    .bind(&anchor.source_slot)
    .bind(serde_json::to_string(&anchor.selectors)?)
    .bind(anchor.body_revision)
    .bind(anchor.body_revision_source.as_str())
    .bind(&anchor.body_sha256)
    .bind(&anchor.purpose)
    .bind(&created_at)
    .bind(&actor)
    .bind(event.local_seq)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The anchor pinned to a comment, if it carries one. Replies never do.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn anchor_on(
    conn: &mut SqliteConnection,
    annotation_id: &str,
) -> Result<Option<CommentAnchor>> {
    Ok(sqlx::query_as(
        "SELECT annotation_id,target_record_id,source_slot,selectors,body_revision,body_revision_source,body_sha256,purpose,created_at,actor,event_seq FROM kernel_comment_anchors WHERE annotation_id = ?",
    )
    .bind(annotation_id)
    .fetch_optional(conn)
    .await?)
}

/// Narrow comment shape for comment-anchor projections only. Authorization
/// uses the complete derived-artifact predicate, including attachments.
pub(crate) fn sql_is_comment(alias: &str) -> String {
    format!(
        "({alias}.kind = '{kind}' AND {alias}.pin_family = '{family}' \
         AND EXISTS(SELECT 1 FROM kernel_record_fields f WHERE f.record_id = {alias}.id AND f.name = 'v1_type' AND f.value_json = '\"Annotation\"') \
         AND EXISTS(SELECT 1 FROM kernel_record_fields f WHERE f.record_id = {alias}.id AND f.name = 'v1_kind' AND f.value_json = '\"comment\"'))",
        kind = crate::v2_standard::v1_compat::KIND,
        family = crate::v2_standard::v1_compat::FAMILY,
    )
}

/// V1's full derived-artifact rule, shared by scalar and set-based visibility.
pub(crate) async fn is_derived_on(conn: &mut SqliteConnection, id: &str) -> Result<bool> {
    Ok(sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM kernel_records r WHERE r.id=? AND {})",
        super::sql_is_derived_artifact("r")
    ))
    .bind(id)
    .fetch_one(conn)
    .await?)
}

pub(crate) async fn derived_terminal_on(
    conn: &mut SqliteConnection,
    id: &str,
) -> Result<Option<String>> {
    let mut current = id.to_owned();
    for depth in 0..=crate::authorization::MAX_DERIVED_BEARER_DEPTH {
        let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id=?) AND NOT EXISTS(SELECT 1 FROM kernel_import_tombstones WHERE record_id=?)")
            .bind(&current).bind(&current).fetch_one(&mut *conn).await?;
        if !live {
            return Ok(None);
        }
        if !is_derived_on(conn, &current).await? {
            return Ok(Some(current));
        }
        if depth == crate::authorization::MAX_DERIVED_BEARER_DEPTH {
            return Ok(None);
        }
        let bearers = bearer_on(conn, &current).await?;
        if bearers.len() != 1 {
            return Ok(None);
        }
        current = bearers.into_iter().next().unwrap();
    }
    Ok(None)
}

/// View through exactly one live bearer chain, using the terminal's home
/// policy and owner floor. `homes` exposes valid homes as (id, view).
/// The artifact's stored home/owner cannot widen or narrow this decision.
pub(crate) fn sql_derived_visible(alias: &str, actor: &str, homes: &str) -> String {
    let derived = super::sql_is_derived_artifact("current_record");
    let terminal = super::sql_is_derived_artifact("terminal");
    let depth = crate::authorization::MAX_DERIVED_BEARER_DEPTH;
    format!("EXISTS(WITH RECURSIVE chain(id,depth) AS (SELECT {alias}.id,0 UNION ALL SELECT l.target_id,c.depth+1 FROM chain c CROSS JOIN main.kernel_records current_record ON current_record.id=c.id JOIN main.kernel_generic_links l ON l.source_id=c.id AND l.relationship='part_of' AND l.active=1 WHERE c.depth<{depth} AND {derived} AND (SELECT count(*) FROM main.kernel_generic_links one WHERE one.source_id=c.id AND one.relationship='part_of' AND one.active=1)=1) SELECT 1 FROM chain c JOIN main.kernel_records terminal ON terminal.id=c.id JOIN ({homes}) terminal_home ON terminal_home.id=terminal.home_id WHERE NOT {terminal} AND (terminal_home.view OR terminal.owner_id={actor}) AND NOT EXISTS(SELECT 1 FROM chain path JOIN main.kernel_import_tombstones t ON t.record_id=path.id))")
}

/// Latest body-lane revision of a record: body text plus the body event's
/// own sequence. Facet, link, and field edits move MAX(seq) without moving
/// the body, so anchors pin this, never the record head.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn body_revision_on(
    conn: &mut SqliteConnection,
    record_id: &str,
) -> Result<Option<(String, i64)>> {
    Ok(
        sqlx::query_as("SELECT body, event_seq FROM kernel_record_bodies WHERE record_id = ?")
            .bind(record_id)
            .fetch_optional(conn)
            .await?,
    )
}

/// Comment creation files in the bearer's home on View of the bearer —
/// never home Edit. Ordinary records keep the shared `create_input_in`
/// home-Edit gate; comments are view-gated so any member who can see a
/// record can annotate it, exactly like v1 filing at ROOT.
///
/// The bearer link, body, and anchor land later in the same act while the
/// chain is still incomplete, fenced by creation (see `creation_fence`):
/// the link MUST come last, after the anchor has read the projected body.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn create_comment_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut crate::act::ActAllocation,
    creator_principal_id: &str,
    family: &str,
    kind: &str,
    input: FieldInput<'_>,
    home_id: &str,
    bearer_id: &str,
) -> Result<String> {
    let home_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)")
            .bind(home_id)
            .fetch_optional(&mut **tx)
            .await?
            .unwrap_or(false);
    if !home_exists {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    kernel_require(&mut *tx, creator_principal_id, bearer_id, Capability::View).await?;
    create_input_admitted_in(
        db,
        tx,
        acts,
        creator_principal_id,
        family,
        kind,
        input,
        home_id,
        None,
        // No home Edit: bearer View above is the whole admission, so any
        // member who can see the record can file the comment.
        false,
        None,
    )
    .await
}

/// The `part_of` bearer link of a comment under construction. No lane
/// authorization of its own: the creation already proved bearer View, and
/// admission fences the write to the owner's incomplete chain. It commits
/// after the anchor so the anchor still reads an incomplete chain.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn append_bearer_link_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut crate::act::ActAllocation,
    principal: &str,
    comment_id: &str,
    bearer_id: &str,
) -> Result<()> {
    append_in(
        db,
        tx,
        AppendSpec {
            record_id: comment_id.into(),
            event_type: "kernel.generic_link_added.v1".into(),
            payload: serde_json::json!({
                "link_id": uuid::Uuid::new_v4().to_string(),
                "source_id": comment_id,
                "target_id": bearer_id,
                "relationship": "part_of",
                "note": null,
            }),
            actor: Some(principal.into()),
        },
        acts,
    )
    .await?;
    Ok(())
}
