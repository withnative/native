//! v1 comment operations on the v2 kernel (HQ cutover W3).
//!
//! Comments are ordinary compat-carrier records (`Annotation`/`comment`):
//! creation, reply, and resolve travel through `create_record` and
//! `update_record` with the v1 thread rules and refusal text, and listing
//! through `get_record` `include_comments` with v1-shaped summaries. The
//! body anchor itself is pinned by `kernel::comments_v2`.
use crate::{
    db::Db,
    kernel::{self, comments_v2},
    Error, Result,
};
use serde_json::{json, Value};
use sqlx::{Sqlite, Transaction};

pub(super) fn is_comment_type(typ: &str, kind: &str) -> bool {
    typ == "Annotation" && kind == "comment"
}

fn refusal(tool: &str, detail: &str) -> Error {
    Error::engine(format!("{tool}: {detail}"))
}

/// Re-render a kernel anchor refusal with the v1 tool prefix. The kernel
/// detail already carries the v1 sentence; only the namespace changes.
fn anchor_refusal(tool: &str, error: Error) -> Error {
    refusal(
        tool,
        error
            .to_string()
            .strip_prefix("kernel comment anchor: ")
            .unwrap_or("anchored comment root must target its part_of bearer's body"),
    )
}

fn optional_text<'a>(args: &'a Value, key: &str) -> Result<Option<&'a str>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        _ => Err(refusal(
            "create_record",
            &format!("{key} must be a string or null"),
        )),
    }
}

/// A validated comment creation: home, lifecycle default, and the
/// optional body anchor pinned against the current target revision.
/// Freshness stays deferred: the revision is recorded, never re-validated.
pub(super) struct CreatePlan {
    pub bearer: String,
    pub home: String,
    pub lifecycle: Option<String>,
    pub anchor: Option<comments_v2::AnchorPayload>,
}

pub(super) async fn prepare_create(
    tx: &mut Transaction<'static, Sqlite>,
    actor: &str,
    args: &Value,
    body: Option<&str>,
    lifecycle: Option<&str>,
    summary: Option<&str>,
) -> Result<CreatePlan> {
    const TOOL: &str = "create_record";
    if !body.is_some_and(|body| !body.trim().is_empty()) {
        return Err(refusal(
            TOOL,
            "Annotation kind:comment requires a nonblank body",
        ));
    }
    let bearers: Vec<String> = args
        .get("links")
        .and_then(Value::as_array)
        .map(|links| {
            links
                .iter()
                .filter(|link| link.get("relationship").and_then(Value::as_str) == Some("part_of"))
                .filter_map(|link| {
                    link.get("target_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .collect()
        })
        .unwrap_or_default();
    if bearers.len() != 1 {
        return Err(refusal(
            TOOL,
            "Annotation kind:comment requires exactly one outgoing part_of link to its bearer",
        ));
    }
    let bearer = bearers.into_iter().next().unwrap();
    // A hidden bearer reads as missing: comments never leak a target the
    // caller cannot see, and the refusal matches a missing record.
    let bearer_view = kernel::read_record_on(tx, actor, &bearer)
        .await?
        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    if lifecycle == Some("resolved") {
        return Err(refusal(
            TOOL,
            "comment roots cannot be created resolved; create open, then resolve with update_record",
        ));
    }
    let position = comments_v2::position_on(tx, &bearer).await?;
    match position {
        comments_v2::Position::Reply => {
            validate_reply_root(tx, TOOL, &bearer).await?;
            if lifecycle.is_some() {
                return Err(refusal(
                    TOOL,
                    "comment replies must have null lifecycle; thread state lives on the root",
                ));
            }
            if summary.is_some() {
                return Err(refusal(
                    TOOL,
                    "comment replies cannot carry a resolution summary",
                ));
            }
            if args.get("target").is_some_and(|target| !target.is_null()) {
                return Err(refusal(
                    TOOL,
                    "comment replies must be targetless; quoted context belongs to the root",
                ));
            }
        }
        comments_v2::Position::Root => match lifecycle {
            None | Some("informational") | Some("open") => {
                if summary.is_some() {
                    return Err(refusal(
                        TOOL,
                        "comment resolution summary is only valid on a resolved root",
                    ));
                }
            }
            Some(other) => {
                return Err(refusal(
                        TOOL,
                        &format!("comment root lifecycle must be null, open, or resolved, or informational \u{2014} the named form of null (got {other})"),
                    ));
            }
        },
    }
    let home = bearer_view.home_id.clone();
    if let Some(explicit) = optional_text(args, "home_id")? {
        if explicit != home {
            return Err(Error::engine(
                "kernel-v2 write: comment home is its bearer's home; omit home_id",
            ));
        }
    }
    let anchor = match (position, args.get("target")) {
        (comments_v2::Position::Reply, _) => None,
        (comments_v2::Position::Root, None | Some(Value::Null)) => None,
        (comments_v2::Position::Root, Some(target)) => {
            Some(prepare_anchor(tx, TOOL, &bearer, target).await?)
        }
    };
    let lifecycle = match position {
        comments_v2::Position::Reply => None,
        comments_v2::Position::Root => Some(
            lifecycle
                .filter(|state| *state != "informational")
                .unwrap_or("informational")
                .to_owned(),
        ),
    };
    Ok(CreatePlan {
        bearer,
        home,
        lifecycle,
        anchor,
    })
}
/// A reply bearer must be a live, well-formed root: exactly one bearer of
/// its own, no nesting, a nonblank body, and a named root lifecycle.
/// Mirrors the v1 reply-bearing checks without the deferred-plan path.
async fn validate_reply_root(
    tx: &mut Transaction<'static, Sqlite>,
    tool: &str,
    root_id: &str,
) -> Result<()> {
    let bearers = comments_v2::bearer_on(tx, root_id).await?;
    if bearers.len() != 1 {
        return Err(refusal(tool, "reply bearer must be a valid root comment"));
    }
    if comments_v2::is_comment_on(tx, &bearers[0]).await? {
        return Err(refusal(
            tool,
            "replies must bear directly on a root comment; reply-to-reply nesting is not supported",
        ));
    }
    // The root target still exists: a reply on a dead thread is refused.
    // Existence, not viewer visibility: the caller already sees the root,
    // and v1 judges the thread by liveness.
    let target_live: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id = ?)")
            .bind(&bearers[0])
            .fetch_one(&mut **tx)
            .await?;
    if !target_live {
        return Err(refusal(tool, "reply bearer has a dead bearer"));
    }
    Ok(())
}

async fn prepare_anchor(
    tx: &mut Transaction<'static, Sqlite>,
    tool: &str,
    bearer: &str,
    target: &Value,
) -> Result<comments_v2::AnchorPayload> {
    let object = target.as_object().ok_or_else(|| {
        refusal(
            tool,
            "anchored comment root must target its part_of bearer's body",
        )
    })?;
    if let Some(extra) = object.keys().find(|key| {
        !matches!(
            key.as_str(),
            "target_record_id" | "source_slot" | "selectors" | "purpose" | "source_pin"
        )
    }) {
        return Err(refusal(tool, &format!("anchor holds no field '{extra}'")));
    }
    let target_record_id = object
        .get("target_record_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            refusal(
                tool,
                "anchored comment root must target its part_of bearer's body",
            )
        })?;
    if target_record_id != bearer {
        return Err(refusal(
            tool,
            "anchored comment root must target its part_of bearer's body",
        ));
    }
    let source_slot = object
        .get("source_slot")
        .and_then(Value::as_str)
        .unwrap_or("");
    let selectors = object.get("selectors").cloned().unwrap_or(Value::Null);
    comments_v2::validate_native_anchor_shape(target_record_id, source_slot, &selectors)
        .map_err(|error| anchor_refusal(tool, error))?;
    let purpose = object
        .get("purpose")
        .and_then(Value::as_str)
        .unwrap_or("comment_context")
        .to_owned();
    if purpose != "comment_context" {
        return Err(refusal(
            tool,
            "anchored comment root must target its part_of bearer's body",
        ));
    }
    let (body, body_seq) = comments_v2::body_revision_on(tx, bearer)
        .await?
        .unwrap_or_default();
    comments_v2::anchor_holds(&body, &selectors).map_err(|error| anchor_refusal(tool, error))?;
    if let Some(pin) = object.get("source_pin") {
        enforce_source_pin(tx, tool, bearer, &body, pin).await?;
    }
    Ok(comments_v2::AnchorPayload {
        target_record_id: bearer.to_owned(),
        source_slot: "body".into(),
        selectors,
        body_revision: body_seq,
        body_revision_source: comments_v2::RevisionSource::NativeBody,
        body_sha256: comments_v2::sha256_hex(&body),
        purpose: Some(purpose),
    })
}

/// A v1 source pin binds the anchor to one exact body event: the pinned
/// event must belong to the bearer, its body must hash to the pinned
/// digest, and that body must still be current. Anything else is a stale
/// pin and the anchor is refused, exactly like v1.
async fn enforce_source_pin(
    tx: &mut Transaction<'static, Sqlite>,
    tool: &str,
    bearer: &str,
    current_body: &str,
    pin: &Value,
) -> Result<()> {
    let stale = || refusal(tool, "the passage anchor source pin is stale");
    let object = pin.as_object().ok_or_else(stale)?;
    if object.len() != 2
        || !object.contains_key("source_event_id")
        || !object.contains_key("source_body_sha256")
    {
        return Err(stale());
    }
    let event_id = object
        .get("source_event_id")
        .and_then(Value::as_str)
        .ok_or_else(stale)?;
    let pinned_sha = object
        .get("source_body_sha256")
        .and_then(Value::as_str)
        .ok_or_else(stale)?;
    if pinned_sha.len() != 64 || !pinned_sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(stale());
    }
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT type, payload FROM content_events WHERE id = ? AND record_id = ?")
            .bind(event_id)
            .bind(bearer)
            .fetch_optional(&mut **tx)
            .await?;
    let Some((event_type, payload)) = row else {
        return Err(stale());
    };
    let payload: Value = serde_json::from_str(&payload).map_err(|_| stale())?;
    let pinned_body = match event_type.as_str() {
        "kernel.body_set.v1" => payload.get("body").and_then(Value::as_str),
        "kernel.import_state.v1" => payload
            .get("state")
            .and_then(|state| state.get("body"))
            .and_then(Value::as_str),
        _ => None,
    }
    .ok_or_else(stale)?;
    if comments_v2::sha256_hex(pinned_body) != pinned_sha || pinned_body != current_body {
        return Err(stale());
    }
    Ok(())
}
/// Whether a stored record is a comment: the compat pin plus the verbatim
/// v1 pair, mirroring the kernel check for the MCP read snapshot.
pub(super) fn record_is_comment(view: &kernel::KernelRecordView) -> bool {
    view.family.as_deref() == Some(crate::v2_standard::v1_compat::FAMILY)
        && view.kind.as_deref() == Some(crate::v2_standard::v1_compat::KIND)
        && view.fields.get("v1_type").and_then(Value::as_str) == Some("Annotation")
        && view.fields.get("v1_kind").and_then(Value::as_str) == Some("comment")
}

/// v1 resolve rules on `update_record`: the one admitted lifecycle write is
/// an atomic root-only `open -> resolved` carrying a nonblank summary.
/// Replies and `informational` roots are not resolvable; a summary may only
/// be written atomically with that transition.
#[allow(clippy::too_many_arguments)]
pub(super) async fn check_update(
    tx: &mut Transaction<'static, Sqlite>,
    id: &str,
    previous: &kernel::KernelRecordView,
    lifecycle_touched: bool,
    lifecycle: Option<&str>,
    summary_touched: bool,
    summary: Option<&str>,
    body: Option<&str>,
    touches_part_of: bool,
) -> Result<()> {
    const TOOL: &str = "update_record";
    if touches_part_of {
        return Err(refusal(
            TOOL,
            "a governed comment's part_of bearer is immutable; create a new comment instead",
        ));
    }
    // A supplied whole-body write must stay nonblank; no body op leaves
    // the stored utterance untouched and is always valid here.
    if let Some(body) = body {
        if body.trim().is_empty() {
            return Err(refusal(
                TOOL,
                "Annotation kind:comment requires a nonblank body",
            ));
        }
    }
    let bearers = comments_v2::bearer_on(tx, id).await?;
    if bearers.len() != 1 {
        return Err(refusal(
            TOOL,
            "Annotation kind:comment requires exactly one outgoing part_of link to its bearer",
        ));
    }
    let position = comments_v2::position_on(tx, &bearers[0]).await?;
    let current_lifecycle = previous.fields.get("lifecycle").and_then(Value::as_str);
    let resulting_lifecycle = if lifecycle_touched {
        lifecycle
    } else {
        current_lifecycle
    };
    let resulting_summary = if summary_touched {
        summary
    } else {
        previous.fields.get("summary").and_then(Value::as_str)
    };
    match position {
        comments_v2::Position::Reply => {
            if resulting_lifecycle.is_some() {
                return Err(refusal(
                    TOOL,
                    "comment replies must have null lifecycle; thread state lives on the root",
                ));
            }
            if resulting_summary.is_some() {
                return Err(refusal(
                    TOOL,
                    "comment replies cannot carry a resolution summary",
                ));
            }
        }
        comments_v2::Position::Root => match resulting_lifecycle {
            None | Some("informational") | Some("open") => {
                if resulting_summary.is_some() {
                    return Err(refusal(
                        TOOL,
                        "comment resolution summary is only valid on a resolved root",
                    ));
                }
            }
            Some("resolved") => {
                if resulting_summary.is_none_or(|summary| summary.trim().is_empty()) {
                    return Err(refusal(
                        TOOL,
                        "resolved comment root requires a nonblank resolution summary",
                    ));
                }
            }
            Some(other) => {
                return Err(refusal(
                    TOOL,
                    &format!("comment root lifecycle must be null, open, or resolved, or informational \u{2014} the named form of null (got {other})"),
                ));
            }
        },
    }
    if lifecycle_touched {
        let subject = match position {
            comments_v2::Position::Reply => {
                "this comment is a reply, and thread state lives on its root".to_owned()
            }
            comments_v2::Position::Root => match current_lifecycle {
                None => format!(
                    "this root is {} (stored as null, the pre-naming spelling) and is not resolvable",
                    crate::comments::INFORMATIONAL
                ),
                Some("informational") => format!(
                    "this root is {} \u{2014} an FYI that is deliberately not resolvable",
                    crate::comments::INFORMATIONAL
                ),
                Some(state) => format!("this root is {state}"),
            },
        };
        if position != comments_v2::Position::Root
            || current_lifecycle != Some(crate::comments::OPEN)
            || resulting_lifecycle != Some(crate::comments::RESOLVED)
            || !summary_touched
            || resulting_summary.is_none_or(|summary| summary.trim().is_empty())
        {
            return Err(refusal(
                TOOL,
                &format!("resolving a comment is an atomic root-only open -> resolved transition with a nonblank summary; {subject}"),
            ));
        }
    } else if summary_touched {
        return Err(refusal(
            TOOL,
            "comment resolution summary may only be written atomically with open -> resolved",
        ));
    }
    Ok(())
}

/// Page of direct thread children for one `get_record` row: roots on an
/// ordinary record (newest first), replies on a root (oldest first). The
/// Each child is authorized in the listing snapshot: refused/interrupted
/// imports can leave an incomplete or duplicate bearer chain, so the parent
/// read alone cannot establish the child's visibility.
pub(super) async fn enrich(
    db: &Db,
    actor: &str,
    record: &kernel::KernelRecordView,
    include: bool,
    limit: usize,
    offset: usize,
) -> Result<Value> {
    let mut snapshot = db.write_pool().begin().await?;
    crate::kernel::app_installs::admit_dispatched_on(&mut snapshot, actor).await?;
    let listing = if record_is_comment(record) {
        comments_v2::Position::Reply
    } else {
        comments_v2::Position::Root
    };
    let mut visible = Vec::new();
    for id in comments_v2::children_on(&mut snapshot, &record.id, listing).await? {
        if let Some(view) = kernel::read_record_on(&mut snapshot, actor, &id).await? {
            visible.push(view);
        }
    }
    let mut result = json!({"comment_count": visible.len()});
    if !include {
        snapshot.rollback().await?;
        return Ok(result);
    }
    // Replies inherit the root's target context without copying anchor rows.
    let root_anchor = if listing == comments_v2::Position::Reply {
        comments_v2::anchor_on(&mut snapshot, &record.id).await?
    } else {
        None
    };
    let mut comments = Vec::new();
    for view in visible.into_iter().skip(offset).take(limit) {
        comments.push(entry(&mut snapshot, actor, &view, listing, &root_anchor).await?);
    }
    snapshot.rollback().await?;
    result["comments"] = Value::Array(comments);
    Ok(result)
}
/// One v1-shaped comment summary. `lifecycle` is the raw stored root
/// state; the typed `lifecycle_interpretation` and `contribution`
/// provenance stay deferred with the freshness/semantic-unit work.
async fn entry(
    snapshot: &mut sqlx::SqliteConnection,
    actor: &str,
    view: &kernel::KernelRecordView,
    listing: comments_v2::Position,
    root_anchor: &Option<comments_v2::CommentAnchor>,
) -> Result<Value> {
    let created_at: String =
        sqlx::query_scalar("SELECT created_at FROM kernel_records WHERE id = ?")
            .bind(&view.id)
            .fetch_one(&mut *snapshot)
            .await?;
    let updated_at: String =
        sqlx::query_scalar("SELECT created_at FROM content_events WHERE seq = ?")
            .bind(view.revision)
            .fetch_one(&mut *snapshot)
            .await?;
    let (position, root_id, anchor) = match listing {
        comments_v2::Position::Root => {
            let anchor = comments_v2::anchor_on(&mut *snapshot, &view.id).await?;
            ("root", view.id.clone(), anchor)
        }
        comments_v2::Position::Reply => (
            "reply",
            anchor_root_id(snapshot, &view.id).await?,
            root_anchor.clone(),
        ),
    };
    let target = match anchor {
        None => Value::Null,
        Some(anchor) => anchor_view(snapshot, actor, &view.id, &anchor).await?,
    };
    Ok(json!({
        "id": view.id,
        "type": "Annotation",
        "kind": "comment",
        "name": view.fields.get("title").cloned().unwrap_or(Value::Null),
        "body": view.body.as_ref().map(|body| json!(body)).unwrap_or(Value::Null),
        "lifecycle": view.fields.get("lifecycle").cloned().unwrap_or(Value::Null),
        "summary": view.fields.get("summary").cloned().unwrap_or(Value::Null),
        "owner_id": view.owner_id.clone().map(Value::String).unwrap_or(Value::Null),
        "created_at": created_at,
        "updated_at": updated_at,
        "archived": view.archived,
        "position": position,
        "root_id": root_id,
        "target": target,
    }))
}

async fn anchor_root_id(snapshot: &mut sqlx::SqliteConnection, reply_id: &str) -> Result<String> {
    let bearers = comments_v2::bearer_on(snapshot, reply_id).await?;
    bearers
        .into_iter()
        .next()
        .ok_or_else(|| Error::engine("kernel comment anchor: reply bearer is missing its root"))
}

/// The root's pinned passage with a same-read validation bit: `current`
/// when the target body still hashes to the pinned digest, `stale` when it
/// moved on, `unavailable` when the caller cannot read the target — in
/// which case the selectors are nulled so no passage leaks. No relocated
/// or conflict states: freshness stays deferred. `body_revision_source`
/// names the revision's origin: the native body lane or the v1 source row.
async fn anchor_view(
    snapshot: &mut sqlx::SqliteConnection,
    actor: &str,
    annotation_id: &str,
    anchor: &comments_v2::CommentAnchor,
) -> Result<Value> {
    let current: Option<String> =
        sqlx::query_scalar("SELECT body FROM kernel_record_bodies WHERE record_id = ?")
            .bind(&anchor.target_record_id)
            .fetch_optional(&mut *snapshot)
            .await?;
    let readable = kernel::read_record_on(snapshot, actor, &anchor.target_record_id)
        .await?
        .is_some();
    let status = if !readable || current.is_none() {
        "unavailable"
    } else if comments_v2::sha256_hex(current.as_deref().unwrap_or("")) == anchor.body_sha256 {
        "current"
    } else {
        "stale"
    };
    let selectors = if status == "unavailable" {
        Value::Null
    } else {
        serde_json::from_str::<Value>(&anchor.selectors).unwrap_or(Value::Null)
    };
    Ok(json!({
        "annotation_id": annotation_id,
        "target_record_id": anchor.target_record_id,
        "source_slot": anchor.source_slot,
        "selectors": selectors,
        "purpose": anchor.purpose.clone().map(Value::String).unwrap_or(Value::Null),
        "body_revision": anchor.body_revision,
        "body_revision_source": anchor.revision_source()?.as_str(),
        "body_sha256": anchor.body_sha256,
        "created_at": anchor.created_at,
        "validation": {"status": status},
    }))
}
// __NEXT4__
