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
    match validate_target_shape_checked_on(tx, id, position, bearer_id).await? {
        Ok(()) => Ok(()),
        Err(shape) => Err(Error::engine(render_shape(tool, &shape))),
    }
}

/// Backend-neutral fold for the optional exact-body target carried by a
/// governed comment. SQLite and portable backend readers call the same fold
/// after gathering their transaction-scoped physical rows.
/// Pure target-shape check returning the expected refusal. No IO is
/// possible here by construction: the target row was already read.
pub(crate) fn check_target_shape(
    position: Position,
    bearer_id: &str,
    target: Option<(&str, &str)>,
) -> std::result::Result<(), CommentShape> {
    let Some((target_record_id, source_slot)) = target else {
        return Ok(());
    };
    if position == Position::Reply {
        return Err(CommentShape::ReplyTargeted);
    }
    if target_record_id != bearer_id || source_slot != "body" {
        return Err(CommentShape::BadAnchor);
    }
    Ok(())
}

pub(crate) fn validate_target_shape(
    tool: &str,
    position: Position,
    bearer_id: &str,
    target: Option<(&str, &str)>,
) -> Result<()> {
    check_target_shape(position, bearer_id, target)
        .map_err(|shape| Error::engine(render_shape(tool, &shape)))
}

/// Target-shape check over a live annotation row. Read failures propagate
/// as the outer error; only the expected shape branches are inner.
async fn validate_target_shape_checked_on(
    tx: &mut Transaction<'_, Sqlite>,
    id: &str,
    position: Position,
    bearer_id: &str,
) -> Result<std::result::Result<(), CommentShape>> {
    validate_target_shape_recorded_on(tx, id, position, bearer_id, &mut Vec::new()).await
}

async fn validate_target_shape_recorded_on(
    tx: &mut Transaction<'_, Sqlite>,
    id: &str,
    position: Position,
    bearer_id: &str,
    proof: &mut Vec<serde_json::Value>,
) -> Result<std::result::Result<(), CommentShape>> {
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
    proof.push(
        serde_json::json!({"template":"eligibility.annotation-target.v1","id":id,"row":target}),
    );
    Ok(check_target_shape(
        position,
        bearer_id,
        target.as_ref().map(|(target_record_id, source_slot)| {
            (target_record_id.as_str(), source_slot.as_str())
        }),
    ))
}

async fn position_for_bearer_checked_on(
    tx: &mut Transaction<'_, Sqlite>,
    bearer_id: &str,
) -> Result<std::result::Result<Position, CommentShape>> {
    position_for_bearer_checked_identity_on(tx, bearer_id, false, &mut Vec::new()).await
}

async fn is_comment_identity_on(
    tx: &mut Transaction<'_, Sqlite>,
    record_type: &str,
    kind: Option<&str>,
    proof: &mut Vec<serde_json::Value>,
) -> Result<bool> {
    proof.push(
        serde_json::json!({"template":"eligibility.kind-input.v1","type":record_type,"kind":kind}),
    );
    let Some(kind) = kind else {
        return Ok(false);
    };
    let mut executor = crate::portable_sql::BorrowedSqliteStatementExecutor::new(tx);
    let resolution =
        crate::meta::kind::resolve_identity_with(&mut executor, record_type, kind).await?;
    Ok(CoreKind::AnnotationComment.matches(&resolution))
}

async fn position_for_bearer_checked_identity_on(
    tx: &mut Transaction<'_, Sqlite>,
    bearer_id: &str,
    minimal_identity: bool,
    proof: &mut Vec<serde_json::Value>,
) -> Result<std::result::Result<Position, CommentShape>> {
    let row = sqlx::query(
        "SELECT type, kind, body, lifecycle, summary, deleted_at
           FROM records WHERE id = ?",
    )
    .bind(bearer_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        proof.push(
            serde_json::json!({"template":"eligibility.bearer-live.v1","id":bearer_id,"row":null}),
        );
        return Ok(Err(CommentShape::MissingBearer));
    };
    let deleted: Option<String> = row.try_get("deleted_at")?;
    proof.push(serde_json::json!({"template":"eligibility.bearer-live.v1","id":bearer_id,"deleted_at":deleted}));
    if deleted.is_some() {
        return Ok(Err(CommentShape::DeletedBearer));
    }
    let record_type: String = row.try_get("type")?;
    let kind: Option<String> = row.try_get("kind")?;
    let governed = if minimal_identity {
        is_comment_identity_on(tx, &record_type, kind.as_deref(), proof).await?
    } else {
        is_governed_comment_on(tx, &record_type, kind.as_deref()).await?
    };
    if !governed {
        return Ok(Ok(Position::Root));
    }
    let bearer_body: Option<String> = row.try_get("body")?;
    let bearer_lifecycle: Option<String> = row.try_get("lifecycle")?;
    let bearer_summary: Option<String> = row.try_get("summary")?;
    proof.push(serde_json::json!({"template":"eligibility.root-state.v1","id":bearer_id,"body":bearer_body,"lifecycle":bearer_lifecycle,"summary":bearer_summary}));
    if let Err(shape) = check_prospective(
        Position::Root,
        bearer_body.as_deref(),
        bearer_lifecycle.as_deref(),
        bearer_summary.as_deref(),
    ) {
        return Ok(Err(shape));
    }

    let root_bearers = bearer_ids_on(tx, bearer_id).await?;
    proof.push(serde_json::json!({"template":"eligibility.bearers.v1","id":bearer_id,"targets":root_bearers}));
    if root_bearers.len() != 1 {
        return Ok(Err(CommentShape::InvalidRootBearer));
    }
    let root_target = sqlx::query("SELECT type, kind, deleted_at FROM records WHERE id = ?")
        .bind(&root_bearers[0])
        .fetch_optional(&mut **tx)
        .await?;
    let Some(root_target) = root_target else {
        return Ok(Err(CommentShape::DeadRootBearer));
    };
    if root_target
        .try_get::<Option<String>, _>("deleted_at")?
        .is_some()
    {
        return Ok(Err(CommentShape::DeadRootBearer));
    }
    let root_target_type: String = root_target.try_get("type")?;
    let root_target_kind: Option<String> = root_target.try_get("kind")?;
    proof.push(serde_json::json!({"template":"eligibility.root-target.v1","id":root_bearers[0],"type":root_target_type,"kind":root_target_kind,"deleted_at":null}));
    let nested = if minimal_identity {
        is_comment_identity_on(tx, &root_target_type, root_target_kind.as_deref(), proof).await?
    } else {
        is_governed_comment_on(tx, &root_target_type, root_target_kind.as_deref()).await?
    };
    if nested {
        return Ok(Err(CommentShape::NestedReply));
    }
    if let Err(shape) =
        validate_target_shape_recorded_on(tx, bearer_id, Position::Root, &root_bearers[0], proof)
            .await?
    {
        return Ok(Err(shape));
    }
    Ok(Ok(Position::Reply))
}

async fn position_for_bearer_on(
    tx: &mut Transaction<'_, Sqlite>,
    tool: &str,
    bearer_id: &str,
) -> Result<Position> {
    match position_for_bearer_checked_on(tx, bearer_id).await? {
        Ok(position) => Ok(position),
        Err(shape) => Err(Error::engine(render_shape(tool, &shape))),
    }
}

pub(crate) fn nonblank(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}

/// Expected thread-shape refusal: provably free of infrastructure failure.
///
/// Every variant is constructed from successfully-read state or pure
/// inputs, never from a failed read. Storage, kind-resolver, and IO
/// failures — including their `Error::engine` mappings such as
/// `stable_storage_error` — surface as the outer `Err` and are never
/// converted here. Callers that need a deterministic refusal match the
/// inner value; callers that must preserve unknown propagate the outer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommentShape {
    BearerCount,
    MissingBearer,
    DeletedBearer,
    InvalidRootBearer,
    DeadRootBearer,
    NestedReply,
    ResolvedRoot,
    BlankBody,
    ReplyLifecycle,
    ReplySummary,
    RootSummary,
    ResolvedNeedsSummary,
    BadRootLifecycle { got: String },
    ReplyTargeted,
    BadAnchor,
}

/// Legacy Engine text for one expected shape refusal. The strings are
/// byte-identical to the historical validator messages; the mapping lives
/// here so ordinary wrappers and the checked path cannot drift apart.
fn render_shape(tool: &str, shape: &CommentShape) -> String {
    match shape {
        CommentShape::BearerCount => format!(
            "{tool}: Annotation kind:comment requires exactly one outgoing part_of link to its bearer"
        ),
        CommentShape::MissingBearer => {
            format!("{tool}: comment bearer does not exist")
        }
        CommentShape::DeletedBearer => {
            format!("{tool}: comment bearer is deleted (tombstoned)")
        }
        CommentShape::InvalidRootBearer => {
            format!("{tool}: reply bearer must be a valid root comment")
        }
        CommentShape::DeadRootBearer => {
            format!("{tool}: reply bearer has a dead bearer")
        }
        CommentShape::NestedReply => format!(
            "{tool}: replies must bear directly on a root comment; reply-to-reply nesting is not supported"
        ),
        CommentShape::ResolvedRoot => format!(
            "{tool}: comment roots cannot be created resolved; create open, then resolve with update_record"
        ),
        CommentShape::BlankBody => format!(
            "{tool}: Annotation kind:comment requires a nonblank body"
        ),
        CommentShape::ReplyLifecycle => format!(
            "{tool}: comment replies must have null lifecycle; thread state lives on the root"
        ),
        CommentShape::ReplySummary => format!(
            "{tool}: comment replies cannot carry a resolution summary"
        ),
        CommentShape::RootSummary => format!(
            "{tool}: comment resolution summary is only valid on a resolved root"
        ),
        CommentShape::ResolvedNeedsSummary => format!(
            "{tool}: resolved comment root requires a nonblank resolution summary"
        ),
        CommentShape::BadRootLifecycle { got } => format!(
            "{tool}: comment root lifecycle must be null, open, or resolved, or informational \u{2014} the named form of null (got {got})"
        ),
        CommentShape::ReplyTargeted => format!(
            "{tool}: comment replies must be targetless; quoted context belongs to the root"
        ),
        CommentShape::BadAnchor => format!(
            "{tool}: anchored comment root must target its part_of bearer's body"
        ),
    }
}

/// Pure prospective check returning the expected refusal. No IO is
/// possible here by construction: only already-available field values.
pub(crate) fn check_prospective(
    position: Position,
    body: Option<&str>,
    lifecycle: Option<&str>,
    summary: Option<&str>,
) -> std::result::Result<(), CommentShape> {
    if !nonblank(body) {
        return Err(CommentShape::BlankBody);
    }
    match position {
        Position::Reply => {
            if lifecycle.is_some() {
                return Err(CommentShape::ReplyLifecycle);
            }
            if summary.is_some() {
                return Err(CommentShape::ReplySummary);
            }
        }
        Position::Root => match lifecycle {
            // Null is the legacy spelling of `informational`; both are open
            // states that carry no resolution summary.
            None | Some(INFORMATIONAL) | Some(OPEN) => {
                if summary.is_some() {
                    return Err(CommentShape::RootSummary);
                }
            }
            Some(RESOLVED) if nonblank(summary) => {}
            Some(RESOLVED) => return Err(CommentShape::ResolvedNeedsSummary),
            Some(other) => {
                return Err(CommentShape::BadRootLifecycle {
                    got: other.to_string(),
                })
            }
        },
    }
    Ok(())
}

pub(crate) fn validate_prospective(
    tool: &str,
    position: Position,
    body: Option<&str>,
    lifecycle: Option<&str>,
    summary: Option<&str>,
) -> Result<()> {
    check_prospective(position, body, lifecycle, summary)
        .map_err(|shape| Error::engine(render_shape(tool, &shape)))
}

/// Checked creation validation: infrastructure failures (SQL, kind
/// resolution, IO) propagate as the outer error; only the expected
/// thread-shape branches are inner. Shares every decision with the legacy
/// wrapper below, which renders identical text.
pub(crate) async fn validate_create_checked_on(
    tx: &mut Transaction<'_, Sqlite>,
    bearer_ids: &[String],
    body: Option<&str>,
    lifecycle: Option<&str>,
    summary: Option<&str>,
) -> Result<std::result::Result<Position, CommentShape>> {
    if bearer_ids.len() != 1 {
        return Ok(Err(CommentShape::BearerCount));
    }
    let position = match position_for_bearer_checked_on(tx, &bearer_ids[0]).await? {
        Ok(position) => position,
        Err(shape) => return Ok(Err(shape)),
    };
    // Creation never manufactures already-resolved history. Resolution is an
    // explicit compare-and-set transition through update_record.
    if lifecycle == Some(RESOLVED) {
        return Ok(Err(CommentShape::ResolvedRoot));
    }
    match check_prospective(position, body, lifecycle, summary) {
        Ok(()) => Ok(Ok(position)),
        Err(shape) => Ok(Err(shape)),
    }
}

pub async fn validate_create_on(
    tx: &mut Transaction<'_, Sqlite>,
    tool: &str,
    bearer_ids: &[String],
    body: Option<&str>,
    lifecycle: Option<&str>,
    summary: Option<&str>,
) -> Result<Position> {
    match validate_create_checked_on(tx, bearer_ids, body, lifecycle, summary).await? {
        Ok(position) => Ok(position),
        Err(shape) => Err(Error::engine(render_shape(tool, &shape))),
    }
}

/// Stored, unchanged-context comment eligibility. Expected CommentShape absence
/// is inner; storage/identity/normalization failures stay outer. Unlike create,
/// a valid resolved stored root is admitted. Canonical prospective/target and
/// unchanged update-transition checks are shared with the public writer.
pub(crate) async fn validate_stored_checked_on(
    tx: &mut Transaction<'_, Sqlite>,
    id: &str,
    proof: &mut Vec<serde_json::Value>,
) -> Result<std::result::Result<(), CommentShape>> {
    // Read and normalize the candidate state just as the ordinary reader does.
    let (body, lifecycle, summary): (Option<String>, Option<String>, Option<String>) =
        sqlx::query_as("SELECT body,lifecycle,summary FROM records WHERE id=?")
            .bind(id)
            .fetch_one(&mut **tx)
            .await?;
    proof.push(serde_json::json!({"template":"eligibility.comment-state.v1","id":id,"body":body,"lifecycle":lifecycle,"summary":summary}));
    let bearers = bearer_ids_on(tx, id).await?;
    proof.push(serde_json::json!({"template":"eligibility.bearers.v1","id":id,"targets":bearers}));
    if bearers.len() != 1 {
        return Ok(Err(CommentShape::BearerCount));
    }
    let position =
        match position_for_bearer_checked_identity_on(tx, &bearers[0], true, proof).await? {
            Ok(position) => position,
            Err(shape) => return Ok(Err(shape)),
        };
    if let Err(shape) =
        validate_target_shape_recorded_on(tx, id, position, &bearers[0], proof).await?
    {
        return Ok(Err(shape));
    }
    // Unchanged stored update has no lifecycle/summary touch.
    Ok(check_prospective(
        position,
        body.as_deref(),
        lifecycle.as_deref(),
        summary.as_deref(),
    ))
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

/// Pins every legacy Engine text rendered from a typed shape refusal.
/// Byte-identity with the historical validator messages is the ordinary
/// compatibility contract; add a case here with any new variant.
#[cfg(test)]
mod shape_text_tests {
    use super::*;

    #[test]
    fn rendered_texts_match_historical_validator_messages() {
        let tool = "create_record";
        let cases: Vec<(CommentShape, String)> = vec![
            (
                CommentShape::BearerCount,
                format!("{tool}: Annotation kind:comment requires exactly one outgoing part_of link to its bearer"),
            ),
            (
                CommentShape::MissingBearer,
                format!("{tool}: comment bearer does not exist"),
            ),
            (
                CommentShape::DeletedBearer,
                format!("{tool}: comment bearer is deleted (tombstoned)"),
            ),
            (
                CommentShape::InvalidRootBearer,
                format!("{tool}: reply bearer must be a valid root comment"),
            ),
            (
                CommentShape::DeadRootBearer,
                format!("{tool}: reply bearer has a dead bearer"),
            ),
            (
                CommentShape::NestedReply,
                format!("{tool}: replies must bear directly on a root comment; reply-to-reply nesting is not supported"),
            ),
            (
                CommentShape::ResolvedRoot,
                format!("{tool}: comment roots cannot be created resolved; create open, then resolve with update_record"),
            ),
            (
                CommentShape::BlankBody,
                format!("{tool}: Annotation kind:comment requires a nonblank body"),
            ),
            (
                CommentShape::ReplyLifecycle,
                format!("{tool}: comment replies must have null lifecycle; thread state lives on the root"),
            ),
            (
                CommentShape::ReplySummary,
                format!("{tool}: comment replies cannot carry a resolution summary"),
            ),
            (
                CommentShape::RootSummary,
                format!("{tool}: comment resolution summary is only valid on a resolved root"),
            ),
            (
                CommentShape::ResolvedNeedsSummary,
                format!("{tool}: resolved comment root requires a nonblank resolution summary"),
            ),
            (
                CommentShape::BadRootLifecycle { got: "snoozed".into() },
                format!("{tool}: comment root lifecycle must be null, open, or resolved, or informational \u{2014} the named form of null (got snoozed)"),
            ),
            (
                CommentShape::ReplyTargeted,
                format!("{tool}: comment replies must be targetless; quoted context belongs to the root"),
            ),
            (
                CommentShape::BadAnchor,
                format!("{tool}: anchored comment root must target its part_of bearer's body"),
            ),
        ];
        assert_eq!(cases.len(), 15, "pin every CommentShape variant");
        for (shape, expected) in &cases {
            assert_eq!(&render_shape(tool, shape), expected, "{shape:?}");
        }
        // The pure decider agrees with the legacy wrapper on representative
        // inputs, so the typed path cannot admit what the wrapper refuses.
        assert_eq!(
            check_prospective(Position::Reply, Some("x"), None, None),
            Ok(())
        );
        assert_eq!(
            check_prospective(Position::Reply, Some("x"), Some("open"), None),
            Err(CommentShape::ReplyLifecycle)
        );
        assert_eq!(check_target_shape(Position::Root, "b", None), Ok(()));
        assert_eq!(
            check_target_shape(Position::Reply, "b", Some(("b", "body"))),
            Err(CommentShape::ReplyTargeted)
        );
    }
}

#[cfg(test)]
mod stored_eligibility_tests {
    use super::*;
    #[tokio::test]
    async fn checked_stored_eligibility_preserves_early_exclusion_before_bad_kind() {
        let db = crate::create_database(":memory:").await.unwrap();
        for (id, kind, body, deleted) in [
            ("comment", "comment", "body", None),
            ("deleted", "", "body", Some("gone")),
            ("root", "comment", "", None),
            ("bad-root-target", "", "body", None),
        ] {
            sqlx::query("INSERT INTO records(id,type,kind,name,body,deleted_at) VALUES (?,'Annotation',?,'probe',?,?)").bind(id).bind(kind).bind(body).bind(deleted).execute(db.write_pool()).await.unwrap();
        }
        sqlx::query("INSERT INTO links(id,source_id,target_id,relationship) VALUES ('probe1','comment','deleted','part_of'),('probe2','root','bad-root-target','part_of')").execute(db.write_pool()).await.unwrap();
        let mut tx = db.write_pool().begin().await.unwrap();
        let mut proof = Vec::new();
        assert_eq!(
            validate_stored_checked_on(&mut tx, "comment", &mut proof)
                .await
                .unwrap(),
            Err(CommentShape::DeletedBearer)
        );
        assert!(!proof
            .iter()
            .any(|v| v["template"] == "eligibility.kind-input.v1"));
        tx.rollback().await.unwrap();
        sqlx::query("UPDATE links SET target_id='root' WHERE id='probe1'")
            .execute(db.write_pool())
            .await
            .unwrap();
        let mut tx = db.write_pool().begin().await.unwrap();
        let mut proof = Vec::new();
        assert_eq!(
            validate_stored_checked_on(&mut tx, "comment", &mut proof)
                .await
                .unwrap(),
            Err(CommentShape::BlankBody)
        );
        assert!(!proof.iter().any(|v| v["id"] == "bad-root-target"));
        tx.rollback().await.unwrap();
    }
}
