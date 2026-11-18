//! Neutral collection reads over a sealed, admitted native member session.
//! No canonical Db, policy lookup, renderer execution or write callback.
use super::*;
use crate::member_copy_kernel_v2::profile::session::NativeMemberReadSession;

pub(crate) async fn open_collection(
    session: &mut NativeMemberReadSession,
    caller: &Caller,
    arguments: Value,
) -> Result<Value> {
    const TOOL: &str = "open_collection";
    let args: RecordIdArgs = parse_args(TOOL, arguments)?;
    let row = sqlx::query("SELECT type,kind FROM records WHERE id=? AND deleted_at IS NULL")
        .bind(&args.id)
        .fetch_optional(&mut **session.transaction())
        .await?
        .ok_or_else(|| Error::engine(format!("{TOOL}: record {} does not exist", args.id)))?;
    let typ: String = row.try_get("type")?;
    let kind: Option<String> = row.try_get("kind")?;
    let Some(kind) = native_collection_kind(&typ, kind.as_deref()) else {
        return Ok(diagnostic(
            "invalid_collection_shape",
            format!(
                "{} is not a live governed Collection kind:query|selection|folder",
                args.id
            ),
            json!({"collection_id":args.id}),
        ));
    };
    let markers = caller.member_schema_incomplete_for();
    if markers
        .iter()
        .any(|marker| marker == "global" || marker == &args.id)
    {
        return Err(Error::unavailable_offline(TOOL, "schema_incomplete"));
    }
    let raw = member_values(session, caller, &args.id, kind).await?;
    validate_member_collection_schema(&raw, markers, crate::events::KERNEL_ROOT_ID)?;
    let mut records = input_records_from_values_in(session.transaction(), raw).await?;
    sort_input_records(&mut records);
    // Authenticated staging has already selected logical identities from the
    // actual native definitions. Keep the existing member renderer shape and
    // closed-endpoint join; listing is not permission to execute a renderer.
    let renderers = incoming_artifacts_member_on(
        session.transaction(),
        &args.id,
        "r.type='Document' AND r.kind='artifact'",
    )
    .await?;
    Ok(json!({
        "status":"opened", "surface":"neutral_table",
        "collection":{"id":args.id,"kind":kind},
        "input":{"version":INPUT_ENVELOPE_VERSION,"records":records},
        "renderers":renderers,
    }))
}

async fn member_values(
    session: &mut NativeMemberReadSession,
    caller: &Caller,
    id: &str,
    kind: &str,
) -> Result<Vec<Value>> {
    if let Some(query) = collection_membership_query(id, kind) {
        return paged_collection_query(
            &mut CollectionQuerySource::NativeMember(session),
            caller,
            &query,
        )
        .await;
    }
    // Only query remains after the common descriptor shape check.
    let raw: Option<String> =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id=? AND key='query'")
            .bind(id)
            .fetch_optional(&mut **session.transaction())
            .await?
            .flatten();
    match super::super::querying::inspect_saved_record_query(raw.as_deref()) {
        super::super::querying::SavedQueryInspection::Valid { query, .. } => {
            if saved_record_query_uses_excluded_input(&query) {
                return Err(Error::unavailable_offline(
                    "open_collection",
                    "saved_query_definition",
                ));
            }
            let all_matching: Option<String> = sqlx::query_scalar(
                "SELECT value FROM facet_values WHERE record_id=? AND key='input_membership'",
            )
            .bind(id)
            .fetch_optional(&mut **session.transaction())
            .await?
            .flatten();
            let mut source = CollectionQuerySource::NativeMember(session);
            // Native online uses this same explicit full-membership opt-in;
            // authored limits/offsets and default page scope remain intact.
            if all_matching.as_deref() == Some("all_matching")
                && query.get("limit").is_none()
                && query.get("offset").is_none()
            {
                return paged_collection_query(&mut source, caller, &query).await;
            }
            let output = source
                .query(caller, "Collection query input", query)
                .await?;
            output
                .get("records")
                .and_then(Value::as_array)
                .cloned()
                .ok_or_else(|| {
                    Error::engine(
                        "Collection kind:query must resolve to records, not a count or aggregate",
                    )
                })
        }
        super::super::querying::SavedQueryInspection::GovernedSql { .. }
        | super::super::querying::SavedQueryInspection::GovernedSqlPinned { .. } => Err(
            Error::unavailable_offline("open_collection", "saved_governed_sql"),
        ),
        super::super::querying::SavedQueryInspection::Invalid { diagnostic }
        | super::super::querying::SavedQueryInspection::UnsupportedVersion { diagnostic, .. } => {
            Err(Error::engine(diagnostic))
        }
    }
}
