//! Existing record presentation folds over the sealed admitted transaction.
use super::*;
use crate::member_copy_kernel_v2::profile::session::NativeMemberReadSession;

pub(crate) async fn get_record(
    session: &mut NativeMemberReadSession,
    caller: &Caller,
    mut arguments: Value,
) -> Result<Value> {
    const TOOL: &str = "get_record";
    if !caller.is_member_copy() || caller.actor() != session.principal() {
        return Err(Error::copy_unavailable());
    }
    if lens::take_as_of(TOOL, &mut arguments)?.is_some() {
        return Err(Error::unavailable_offline(TOOL, "as_of"));
    }
    let arguments = crate::mcp::record_ref::normalize_operation_record_selector(TOOL, arguments)?;
    let mut args: GetRecordArgs = parse_args(TOOL, arguments)?;
    args.validate_ids()?;
    args.validate_interpretation_bound()?;
    let opts = args.enrich_options();
    opts.validate()?;
    for id in &mut args.ids {
        *id = resolve_reference(session, id, TOOL).await?;
    }
    let resolve = args.resolve.unwrap_or(true);
    let history = args.include_history_summary.unwrap_or(false);
    let interpretation = args.include_interpretation.unwrap_or(false);
    let mut records = read::get_records_native_member(session, &args.ids, opts).await?;
    let mut link_ctx = LinkSummaryContext::default();
    for item in &mut records {
        let read::BatchGetItem::Found(record) = item else {
            continue;
        };
        enrich_record(session, caller, record, opts, &mut link_ctx).await?;
    }
    let mut items = supplement_get_record_items(
        &mut RecordSupplementSource::NativeMember(session),
        caller,
        records,
        resolve,
    )
    .await?;
    let anchors: std::collections::HashSet<String> =
        sqlx::query_scalar("SELECT annotation_id FROM main.comment_anchors")
            .fetch_all(&mut **session.transaction())
            .await?
            .into_iter()
            .collect();
    inject_member_record_markers_with_custody(
        &mut items,
        history,
        opts.include_citations,
        &anchors,
        true,
    );
    for item in items
        .as_array_mut()
        .expect("batch get serializes as an array")
    {
        if item["status"] != "found" {
            continue;
        }
        annotate_body_digest(item);
        let native_identity: String = sqlx::query_scalar(
            "SELECT native_identity FROM main.member_record_metadata WHERE record_id=?",
        )
        .bind(item["id"].as_str().expect("found record id"))
        .fetch_one(&mut **session.transaction())
        .await?;
        item["kernel_v2"] = serde_json::from_str(&native_identity)?;
        if item["type"] == "Document" && item["kind"] == "attachment" {
            let metadata: Option<String> = sqlx::query_scalar(
                "SELECT blob_metadata FROM main.member_record_metadata WHERE record_id=?",
            )
            .bind(item["id"].as_str().expect("found record id"))
            .fetch_one(&mut **session.transaction())
            .await?;
            // NULL is the source API's selected None; missing metadata rows
            // and source/storage errors never become an absent blob.
            item["blob"] = match metadata {
                Some(value) => serde_json::from_str(&value)?,
                None => Value::Null,
            };
        }
        if interpretation {
            item["interpretation"] = member_section_marker("interpretation");
        }
        let root_anchored = item["id"].as_str().is_some_and(|id| anchors.contains(id));
        if let Some(comments) = item.get_mut("comments").and_then(Value::as_array_mut) {
            for comment in comments {
                let context: Option<String> = sqlx::query_scalar(
                    "SELECT comment_context FROM main.member_record_metadata WHERE record_id=?",
                )
                .bind(comment["id"].as_str().expect("validated comment id"))
                .fetch_one(&mut **session.transaction())
                .await?;
                let context: Value =
                    serde_json::from_str(&context.ok_or_else(Error::copy_unavailable)?)?;
                comment["position"] = context
                    .get("position")
                    .ok_or_else(Error::copy_unavailable)?
                    .clone();
                comment["root_id"] = context
                    .get("root_id")
                    .ok_or_else(Error::copy_unavailable)?
                    .clone();
                comment["contribution"] = member_section_marker("contribution");
                if root_anchored
                    || comment["id"]
                        .as_str()
                        .is_some_and(|id| anchors.contains(id))
                {
                    comment["target"] = member_section_marker("citation");
                }
            }
        }
    }
    annotate_native_member_references(session.transaction(), &mut items).await?;
    Ok(get_record_window_response(
        items,
        resolve,
        opts,
        history,
        interpretation,
    ))
}

async fn enrich_record(
    session: &mut NativeMemberReadSession,
    caller: &Caller,
    record: &mut read::EnrichedRecord,
    opts: read::EnrichOptions,
    context: &mut LinkSummaryContext,
) -> Result<()> {
    // Every endpoint/body belongs to this admitted current-state closure.
    attach_link_summaries_in_tx(session.transaction(), caller, record, context).await?;
    attach_mentions_in(session.transaction(), caller, record, opts).await
}

pub(crate) async fn render_record(
    session: &mut NativeMemberReadSession,
    caller: &Caller,
    arguments: Value,
) -> Result<Value> {
    const TOOL: &str = "render_record";
    if !caller.is_member_copy() || caller.actor() != session.principal() {
        return Err(Error::copy_unavailable());
    }
    let mut args: RenderRecordArgs = parse_args(TOOL, arguments)?;
    args.id = resolve_reference(session, &args.id, TOOL).await?;
    let opts = read::EnrichOptions::default();
    // Keep the typed record's internal raw carrier for the existing Markdown
    // renderer. JSON Get deliberately omits that field; round-tripping through
    // its response would lose actual lifecycle state and presentation facts.
    let mut records =
        read::get_records_native_member(session, std::slice::from_ref(&args.id), opts).await?;
    let Some(read::BatchGetItem::Found(mut record)) = records.pop() else {
        return Err(Error::engine(format!(
            "{TOOL}: record {} does not exist",
            args.id
        )));
    };
    let mut context = LinkSummaryContext::default();
    enrich_record(session, caller, &mut record, opts, &mut context).await?;
    if let Some(superseded) = record.superseded_by.as_mut() {
        let ids = superseded
            .items
            .iter()
            .map(|item| item.id.clone())
            .collect::<Vec<_>>();
        let references = member_display_references_in_tx(session.transaction(), &ids).await?;
        apply_typed_superseded_references(superseded, &references);
    }
    let names = endpoint_names_in(session.transaction(), &record).await?;
    let markdown = render_enriched_record_markdown(&record, &names);
    let mut output = json!({"id":args.id,"markdown":markdown});
    if args.include_interpretation.unwrap_or(false) {
        output["interpretation"] = member_section_marker("render_interpretation");
    }
    Ok(output)
}

/// Exact ids retain precedence. A stored source-safe reference (or its
/// extension) is a usable address; a shorter/withheld reference is unresolved.
/// No slice-local uniqueness is promoted to a global claim or output prefix.
pub(crate) async fn resolve_reference(
    session: &mut NativeMemberReadSession,
    input: &str,
    tool: &str,
) -> Result<String> {
    let input = if input == crate::schema::ROOT_RECORD_ID {
        crate::events::KERNEL_ROOT_ID
    } else {
        input
    };
    let present: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM records WHERE id=?)")
        .bind(input)
        .fetch_one(&mut **session.transaction())
        .await?;
    if present {
        return Ok(input.to_owned());
    }
    let Some(prefix) = crate::mcp::record_ref::canonical_prefix(input) else {
        return Ok(input.to_owned());
    };
    let upper = format!("{prefix}{}", crate::mcp::record_ref::PREFIX_SENTINEL);
    let rows = sqlx::query("SELECT r.id,m.display_reference FROM records r JOIN main.member_record_metadata m ON m.record_id=r.id WHERE r.id>=? AND r.id<? AND r.deleted_at IS NULL AND length(r.id)=36 ORDER BY r.id LIMIT ?")
        .bind(&prefix).bind(upper).bind(crate::mcp::record_ref::MAX_CANDIDATES).fetch_all(&mut **session.transaction()).await?;
    let mut eligible = Vec::new();
    for row in rows {
        let id: String = row.try_get("id")?;
        let reference: Option<String> = row.try_get("display_reference")?;
        if !crate::mcp::record_ref::is_canonical_uuid(&id) {
            continue;
        }
        if reference
            .as_deref()
            .and_then(crate::mcp::record_ref::canonical_prefix)
            .is_some_and(|safe| prefix.starts_with(&safe))
        {
            eligible.push(id);
        }
    }
    match eligible.as_slice() {
        [] => Ok(input.to_owned()),
        [id] => Ok(id.clone()),
        _ => Err(Error::engine(format!(
            "{tool}: record id prefix is ambiguous within the admitted member copy"
        ))),
    }
}
