//! Reduced bootstrap from one admitted native generation. Legacy imported
//! source association is a separate selected member projection, never native
//! workspace authority or an inferred private-home permission.
use super::*;
use crate::member_copy_kernel_v2::profile::session::NativeMemberReadSession;

pub(crate) async fn native_member_bootstrap(
    session: &mut NativeMemberReadSession,
    caller: &Caller,
    arguments: Value,
) -> Result<Value> {
    if !caller.is_member_copy() || caller.actor() != session.principal() {
        return Err(Error::copy_unavailable());
    }
    let _: BootstrapArgs = parse_args("bootstrap", arguments)?;
    if caller
        .member_schema_incomplete_for()
        .iter()
        .any(|scope| scope == "global")
    {
        return Err(Error::unavailable_offline("bootstrap", "schema_incomplete"));
    }
    let run_key = match caller.run_key() {
        Some(key) => key.to_owned(),
        None => crate::runkey::mint_fresh_agent_run(&HashSet::new())?,
    };
    let context = sqlx::query(
        "SELECT principal,instructions,instruction_source_ids,source_context FROM main.member_context",
    )
    .fetch_one(&mut **session.transaction())
    .await?;
    let principal: Value = serde_json::from_str(&context.try_get::<String, _>("principal")?)?;
    if principal["principal_id"].as_str() != Some(caller.actor()) {
        return Err(Error::copy_unavailable());
    }
    let instructions: Value = serde_json::from_str(&context.try_get::<String, _>("instructions")?)?;
    let instruction_sources: String = context.try_get("instruction_source_ids")?;
    let source_context =
        crate::member_copy_kernel_v2::profile::source_context::MemberSourceContext::decode(
            &context.try_get::<String, _>("source_context")?,
        )
        .map_err(|_| Error::copy_unavailable())?;
    let source_context =
        crate::member_copy_kernel_v2::profile::source_context::MemberSourceContext::response(
            source_context,
        );
    let root = session
        .virtual_root()
        .await?
        .ok_or_else(|| Error::engine(crate::kernel::HIDDEN_OR_MISSING))?;
    let root_id = root.kernel_root_id.clone();
    let live = format!(
        "{} AND r.archived=0",
        crate::mcp::kernel_v2::native_query_hidden_predicate("r", &[])
    );
    let records_visible: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM records r WHERE r.deleted_at IS NULL AND {live}"
    ))
    .fetch_one(&mut **session.transaction())
    .await?;
    let people:i64=sqlx::query_scalar(&format!("SELECT COUNT(DISTINCT r.id) FROM records r JOIN main.bindings b ON b.record_id=r.id WHERE r.deleted_at IS NULL AND {live} AND r.type='Entity' AND r.kind='person' AND b.system='account' AND b.is_canonical=1"))
        .fetch_one(&mut **session.transaction()).await?;
    let raw_name = root.name.clone();
    let (name, name_truncated) = bounded_text(&raw_name, MAX_PREVIEW_NAME_CHARS);
    let workspace = json!({
        "scope":"one connected Native database and one primary workspace",
        "primary_workspace":{"id":root_id,"name":name,"name_truncated":name_truncated},
        "records_visible":records_visible,"record_count_truncated":false,
        "record_count_qualification":"admitted slice rows visible to this member; hidden, withdrawn and nonexistent records are absent, never zeroed",
        "registered_humans_visible":people,"human_count_truncated":false,
        "human_count_qualification":"caller-bound verified Person records in the admitted native slice; not proof of an exhaustive roster",
        "known_limitations":["personal-home and multi-workspace orientation are outside the current native-ce bootstrap horizon"],
    });
    let root_nodes = crate::query::tree::descendants_native_member(
        session,
        &root.id,
        crate::query::tree::TreeOptions {
            max_depth: 0,
            max_children_per_node: 0,
            ..Default::default()
        },
    )
    .await?;
    let [node] = root_nodes.as_slice() else {
        return Err(Error::copy_unavailable());
    };
    let roots = json!({"items":[{"id":node.id,"type":node.record_type,"kind":node.kind,"name":node.name,"persistence":node.persistence,"child_count":node.child_count}],"total":1,
        "continuation":{"tool":"get_structure","arguments":{"root_id":crate::schema::ROOT_RECORD_ID}}});
    let observed_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let current_world = current_world(session, caller, &observed_at, instruction_sources).await?;
    let version: i64 = sqlx::query_scalar("PRAGMA main.user_version")
        .fetch_one(&mut **session.transaction())
        .await?;
    let engine = json!({"name":"native-kernel-v2","version":ENGINE_VERSION,"schema_version":0,"user_version":version});
    finish_member_bootstrap(MemberBootstrapParts {
        run_key,
        intent_declared: caller.intent().is_some(),
        principal,
        source_context: Some(source_context),
        workspace,
        current_world,
        instructions,
        engine,
        roots,
    })
}

async fn current_world(
    session: &mut NativeMemberReadSession,
    caller: &Caller,
    observed_at: &str,
    instruction_sources: String,
) -> Result<Value> {
    let hidden = crate::mcp::kernel_v2::native_query_hidden_predicate("r", &[]);
    let statement=format!("SELECT r.id,r.type,r.kind,r.name,r.home_id,r.lifecycle,COALESCE(r.last_activity_at,r.updated_at,r.created_at) AS observed_activity_at FROM records r WHERE r.deleted_at IS NULL AND {hidden} AND r.archived=0 AND r.id NOT IN ('kernel:root','native:root','native:unfiled') AND r.id NOT LIKE 'native:%' AND r.id NOT IN (SELECT value FROM json_each(?)) AND NOT EXISTS(SELECT 1 FROM main.bindings b WHERE b.record_id=r.id AND b.system='account' AND b.is_canonical=1) ORDER BY observed_activity_at DESC,r.id LIMIT ?");
    let rows = sqlx::query(&statement)
        .bind(instruction_sources)
        .bind((CURRENT_WORLD_SCAN_LIMIT + 1) as i64)
        .fetch_all(&mut **session.transaction())
        .await?;
    let scan_truncated = rows.len() > CURRENT_WORLD_SCAN_LIMIT;
    let rows = rows
        .into_iter()
        .take(CURRENT_WORLD_SCAN_LIMIT)
        .collect::<Vec<_>>();
    for row in &rows {
        if let Some(home) = row.try_get::<Option<String>, _>("home_id")? {
            if crate::mcp::member_serving::member_schema_incomplete_applies(caller, &home) {
                return Err(Error::unavailable_offline("bootstrap", "schema_incomplete"));
            }
        }
    }
    let schema_rows = crate::query::cascade::schema_config_rows_on(session.transaction()).await?;
    let interpreter =
        LifecycleInterpreter::load_from_connection(session.transaction(), schema_rows).await?;
    let mut stubs = rows
        .iter()
        .map(|r| Ok(json!({"id":r.try_get::<String,_>("id")?})))
        .collect::<Result<Vec<_>>>()?;
    super::super::lifecycle::annotate_superseded_refs_in_tx(
        session.transaction(),
        caller,
        &mut stubs,
    )
    .await?;
    let superseded = stubs
        .into_iter()
        .filter_map(|stub| {
            Some((
                stub.get("id")?.as_str()?.to_owned(),
                stub.get("superseded_by")?.clone(),
            ))
        })
        .collect();
    finish_member_current_world(
        &rows,
        &interpreter,
        &superseded,
        observed_at,
        scan_truncated,
    )
}
