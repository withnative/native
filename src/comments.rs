//! Governed `Annotation:comment` write invariants.
//!
//! Comments use the ordinary record/link event stream.  These guards keep that
//! generic substrate from admitting shapes the comment reader cannot safely
//! interpret: one immutable bearer, flat replies, and a root-owned lifecycle.

use sqlx::{Row, Sqlite, Transaction};

use crate::error::{Error, Result};
use crate::generated::kinds::CoreKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    Root,
    Reply,
}

/// The FYI root: deliberately not resolvable, deliberately not an open thread.
/// This is the NAME of the state a pre-naming root expressed by storing null,
/// so every reader must treat the two identically.
pub const INFORMATIONAL: &str = "informational";
/// A root awaiting an answer — the only state `resolved` may be reached from.
pub const OPEN: &str = "open";
/// A closed root, which owns a nonblank resolution summary.
pub const RESOLVED: &str = "resolved";

/// Read a stored root lifecycle as its named state. Null is legacy
/// `informational`, not a missing value: two rows in a live database predate
/// the name and must keep reading and writing exactly as they always did.
pub fn root_state(lifecycle: Option<&str>) -> &str {
    lifecycle.unwrap_or(INFORMATIONAL)
}

/// The lifecycle a freshly created comment stores. A root that names no state
/// is an FYI, so it is born `informational` rather than null; a reply's thread
/// state lives on its root and stays null.
pub fn created_lifecycle(position: Position, lifecycle: Option<&str>) -> Option<String> {
    match position {
        Position::Reply => lifecycle.map(str::to_owned),
        Position::Root => Some(root_state(lifecycle).to_owned()),
    }
}

pub async fn is_governed_comment_on(
    tx: &mut Transaction<'_, Sqlite>,
    record_type: &str,
    kind: Option<&str>,
) -> Result<bool> {
    let Some(kind) = kind else { return Ok(false) };
    let resolution = crate::meta::kind::resolve_on(tx, record_type, kind).await?;
    Ok(CoreKind::AnnotationComment.matches(&resolution))
}

async fn bearer_ids_on(tx: &mut Transaction<'_, Sqlite>, id: &str) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT target_id FROM links
          WHERE source_id = ? AND relationship = 'part_of'
          ORDER BY target_id",
    )
    .bind(id)
    .fetch_all(&mut **tx)
    .await?)
}

async fn validate_target_shape_on(
    tx: &mut Transaction<'_, Sqlite>,
    tool: &str,
    id: &str,
    position: Position,
    bearer_id: &str,
) -> Result<()> {
    let target = sqlx::query(
        "SELECT target_record_id, source_slot FROM annotation_targets WHERE annotation_id = ?",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    let target = target
        .as_ref()
        .map(|target| {
            Ok::<_, sqlx::Error>((
                target.try_get::<String, _>("target_record_id")?,
                target.try_get::<String, _>("source_slot")?,
            ))
        })
        .transpose()?;
    validate_target_shape(
        tool,
        position,
        bearer_id,
        target.as_ref().map(|(target_record_id, source_slot)| {
            (target_record_id.as_str(), source_slot.as_str())
        }),
    )
}

/// Backend-neutral fold for the optional exact-body target carried by a
/// governed comment. SQLite and portable backend readers call the same fold
/// after gathering their transaction-scoped physical rows.
pub(crate) fn validate_target_shape(
    tool: &str,
    position: Position,
    bearer_id: &str,
    target: Option<(&str, &str)>,
) -> Result<()> {
    let Some((target_record_id, source_slot)) = target else {
        return Ok(());
    };
    if position == Position::Reply {
        return Err(Error::engine(format!(
            "{tool}: comment replies must be targetless; quoted context belongs to the root"
        )));
    }
    if target_record_id != bearer_id || source_slot != "body" {
        return Err(Error::engine(format!(
            "{tool}: anchored comment root must target its part_of bearer's body"
        )));
    }
    Ok(())
}

async fn position_for_bearer_on(
    tx: &mut Transaction<'_, Sqlite>,
    tool: &str,
    bearer_id: &str,
) -> Result<Position> {
    let row = sqlx::query(
        "SELECT type, kind, body, lifecycle, summary, deleted_at
           FROM records WHERE id = ?",
    )
    .bind(bearer_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| Error::engine(format!("{tool}: comment bearer does not exist")))?;
    if row.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        return Err(Error::engine(format!(
            "{tool}: comment bearer is deleted (tombstoned)"
        )));
    }
    let record_type: String = row.try_get("type")?;
    let kind: Option<String> = row.try_get("kind")?;
    if !is_governed_comment_on(tx, &record_type, kind.as_deref()).await? {
        return Ok(Position::Root);
    }
    let bearer_body: Option<String> = row.try_get("body")?;
    let bearer_lifecycle: Option<String> = row.try_get("lifecycle")?;
    let bearer_summary: Option<String> = row.try_get("summary")?;
    validate_prospective(
        tool,
        Position::Root,
        bearer_body.as_deref(),
        bearer_lifecycle.as_deref(),
        bearer_summary.as_deref(),
    )?;

    let root_bearers = bearer_ids_on(tx, bearer_id).await?;
    if root_bearers.len() != 1 {
        return Err(Error::engine(format!(
            "{tool}: reply bearer must be a valid root comment"
        )));
    }
    let root_target = sqlx::query("SELECT type, kind, deleted_at FROM records WHERE id = ?")
        .bind(&root_bearers[0])
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| Error::engine(format!("{tool}: reply bearer has a dead bearer")))?;
    if root_target
        .try_get::<Option<String>, _>("deleted_at")?
        .is_some()
    {
        return Err(Error::engine(format!(
            "{tool}: reply bearer has a dead bearer"
        )));
    }
    let root_target_type: String = root_target.try_get("type")?;
    let root_target_kind: Option<String> = root_target.try_get("kind")?;
    if is_governed_comment_on(tx, &root_target_type, root_target_kind.as_deref()).await? {
        return Err(Error::engine(format!(
            "{tool}: replies must bear directly on a root comment; reply-to-reply nesting is not supported"
        )));
    }
    validate_target_shape_on(tx, tool, bearer_id, Position::Root, &root_bearers[0]).await?;
    Ok(Position::Reply)
}

pub(crate) fn nonblank(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}

pub(crate) fn validate_prospective(
    tool: &str,
    position: Position,
    body: Option<&str>,
    lifecycle: Option<&str>,
    summary: Option<&str>,
) -> Result<()> {
    if !nonblank(body) {
        return Err(Error::engine(format!(
            "{tool}: Annotation kind:comment requires a nonblank body"
        )));
    }
    match position {
        Position::Reply => {
            if lifecycle.is_some() {
                return Err(Error::engine(format!(
                    "{tool}: comment replies must have null lifecycle; thread state lives on the root"
                )));
            }
            if summary.is_some() {
                return Err(Error::engine(format!(
                    "{tool}: comment replies cannot carry a resolution summary"
                )));
            }
        }
        Position::Root => match lifecycle {
            // Null is the legacy spelling of `informational`; both are open
            // states that carry no resolution summary.
            None | Some(INFORMATIONAL) | Some(OPEN) => {
                if summary.is_some() {
                    return Err(Error::engine(format!(
                        "{tool}: comment resolution summary is only valid on a resolved root"
                    )));
                }
            }
            Some(RESOLVED) if nonblank(summary) => {}
            Some(RESOLVED) => {
                return Err(Error::engine(format!(
                    "{tool}: resolved comment root requires a nonblank resolution summary"
                )))
            }
            Some(other) => {
                return Err(Error::engine(format!(
                    "{tool}: comment root lifecycle must be null, open, or resolved, or informational \u{2014} the named form of null (got {other})"
                )))
            }
        },
    }
    Ok(())
}

pub async fn validate_create_on(
    tx: &mut Transaction<'_, Sqlite>,
    tool: &str,
    bearer_ids: &[String],
    body: Option<&str>,
    lifecycle: Option<&str>,
    summary: Option<&str>,
) -> Result<Position> {
    if bearer_ids.len() != 1 {
        return Err(Error::engine(format!(
            "{tool}: Annotation kind:comment requires exactly one outgoing part_of link to its bearer"
        )));
    }
    let position = position_for_bearer_on(tx, tool, &bearer_ids[0]).await?;
    // Creation never manufactures already-resolved history. Resolution is an
    // explicit compare-and-set transition through update_record.
    if lifecycle == Some(RESOLVED) {
        return Err(Error::engine(format!(
            "{tool}: comment roots cannot be created resolved; create open, then resolve with update_record"
        )));
    }
    validate_prospective(tool, position, body, lifecycle, summary)?;
    Ok(position)
}

#[allow(clippy::too_many_arguments)]
pub async fn validate_update_on(
    tx: &mut Transaction<'_, Sqlite>,
    tool: &str,
    id: &str,
    current_type: &str,
    current_kind: Option<&str>,
    resulting_kind: Option<&str>,
    resulting_body: Option<&str>,
    current_lifecycle: Option<&str>,
    resulting_lifecycle: Option<&str>,
    resulting_summary: Option<&str>,
    kind_touched: bool,
    lifecycle_touched: bool,
    summary_touched: bool,
) -> Result<()> {
    let current_is_comment = is_governed_comment_on(tx, current_type, current_kind).await?;
    let resulting_is_comment = is_governed_comment_on(tx, current_type, resulting_kind).await?;
    if !current_is_comment {
        if resulting_is_comment {
            return Err(Error::engine(format!(
                "{tool}: governed comment identity cannot be added by updating kind; create a comment with its bearer atomically"
            )));
        }
        return Ok(());
    }
    if !resulting_is_comment {
        return Err(Error::engine(format!(
            "{tool}: governed comment identity cannot be removed by updating kind"
        )));
    }
    if kind_touched && current_kind != resulting_kind {
        // Aliases may normalize to the same governed identity above, but a
        // comment's authored kind token is not an escape hatch from its rules.
        let current = crate::meta::kind::resolve_on(
            tx,
            current_type,
            current_kind.expect("governed comment has a kind"),
        )
        .await?;
        let resulting = crate::meta::kind::resolve_on(
            tx,
            current_type,
            resulting_kind.expect("governed comment has a resulting kind"),
        )
        .await?;
        if !CoreKind::AnnotationComment.matches(&current)
            || !CoreKind::AnnotationComment.matches(&resulting)
        {
            return Err(Error::engine(format!(
                "{tool}: governed comment identity cannot be changed"
            )));
        }
    }

    let bearers = bearer_ids_on(tx, id).await?;
    if bearers.len() != 1 {
        return Err(Error::engine(format!(
            "{tool}: Annotation kind:comment requires exactly one outgoing part_of link to its bearer"
        )));
    }
    let position = position_for_bearer_on(tx, tool, &bearers[0]).await?;
    validate_target_shape_on(tx, tool, id, position, &bearers[0]).await?;
    validate_prospective(
        tool,
        position,
        resulting_body,
        resulting_lifecycle,
        resulting_summary,
    )?;

    assert_resolution_transition(
        tool,
        position,
        current_lifecycle,
        resulting_lifecycle,
        resulting_summary,
        lifecycle_touched,
        summary_touched,
    )
}

/// The one lifecycle transition a governed comment admits: an atomic root-only
/// `open -> resolved` carrying a nonblank summary. Shared by both enforcement
/// paths so the rule and its diagnosis cannot drift apart.
///
/// The refusal NAMES the state the root is actually in. Saying only that the
/// transition must start from `open` is what let `informational` stay invisible
/// to a previous reader, who took a legitimately unresolvable FYI for a bug.
pub(crate) fn assert_resolution_transition(
    tool: &str,
    position: Position,
    current_lifecycle: Option<&str>,
    resulting_lifecycle: Option<&str>,
    resulting_summary: Option<&str>,
    lifecycle_touched: bool,
    summary_touched: bool,
) -> Result<()> {
    if lifecycle_touched {
        if position != Position::Root
            || current_lifecycle != Some(OPEN)
            || resulting_lifecycle != Some(RESOLVED)
            || !summary_touched
            || !nonblank(resulting_summary)
        {
            return Err(Error::engine(format!(
                "{tool}: resolving a comment is an atomic root-only open -> resolved transition with a nonblank summary; {}",
                transition_subject(position, current_lifecycle)
            )));
        }
    } else if summary_touched {
        return Err(Error::engine(format!(
            "{tool}: comment resolution summary may only be written atomically with open -> resolved"
        )));
    }
    Ok(())
}

fn transition_subject(position: Position, current_lifecycle: Option<&str>) -> String {
    match position {
        Position::Reply => {
            "this comment is a reply, and thread state lives on its root".to_string()
        }
        Position::Root => match current_lifecycle {
            None => format!(
                "this root is {INFORMATIONAL} (stored as null, the pre-naming spelling) and is not resolvable"
            ),
            Some(INFORMATIONAL) => format!(
                "this root is {INFORMATIONAL} \u{2014} an FYI that is deliberately not resolvable"
            ),
            Some(state) => format!("this root is {state}"),
        },
    }
}

pub async fn assert_bearer_immutable_on(
    tx: &mut Transaction<'_, Sqlite>,
    tool: &str,
    source_id: &str,
    relationship: &str,
) -> Result<()> {
    if relationship != "part_of" {
        return Ok(());
    }
    let row = sqlx::query("SELECT type, kind FROM records WHERE id = ? AND deleted_at IS NULL")
        .bind(source_id)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(row) = row else { return Ok(()) };
    let record_type: String = row.try_get("type")?;
    let kind: Option<String> = row.try_get("kind")?;
    if is_governed_comment_on(tx, &record_type, kind.as_deref()).await? {
        return Err(Error::engine(format!(
            "{tool}: a governed comment's part_of bearer is immutable; create a new comment instead"
        )));
    }
    Ok(())
}
