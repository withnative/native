//! The tool surface — the v1 tools, two MCP App launchers, and citation tools, grouped
//! by build stage, registered over the stage-2 seam.
//!
//! Every handler here follows the seam's one hard rule (decision 2231ad3):
//! structured data out, no formatting. Handlers parse their arguments with
//! serde (`deny_unknown_fields` throughout — an unknown argument is a caller
//! bug worth surfacing, not noise to ignore), call the read layer (`query::*`)
//! or the write API (`store`), and return `serde_json::Value`.
//!
//! Registration is additive per stage: each transport-neutral stage module
//! exposes a `register_*` function and [`register_surface_tools`] calls them
//! all. The universal snapshot tool is registered separately because its
//! runtime mechanism is captured through [`SnapshotSourceRef`].

pub mod apps;
pub mod artifact_interactions;
pub mod artifacts;
pub mod attachments;
pub mod attribution;
pub mod canvas;
pub mod change_summaries;
pub mod citations;
pub mod create_many;
pub mod event_context;
#[cfg(feature = "experimental-agent-intents")]
pub mod experimental_agent_intents;
pub mod exploration;
pub mod export;
pub mod facets;
pub mod history;
pub mod identity;
pub mod instructions;
pub mod intent;
pub mod interventions;
pub mod lifecycle;
pub mod links;
pub mod messaging;
pub mod meta;
pub mod mint;
pub mod observations;
pub mod orientation;
pub mod policy;
pub mod querying;
pub mod quickstart;
pub mod record_shape;
pub mod relationships;
pub mod resolution;
pub mod suggestions;
pub mod work;

use serde::de::DeserializeOwned;
use serde_json::Value;
use sqlx::{Row, Sqlite, Transaction};

use crate::authorization::{self, Capability, Principal};
use crate::error::{Error, Result};

use super::registry::{Caller, ToolRegistry};
use super::SnapshotSourceRef;

/// Register every shipped surface tool, in surface order (registration order
/// is the `tools/list` order). Stages extend this as they land; today: stage 3
/// (orientation 1–4, lifecycle 5–10), stage 4 (history 11–12, links 13,
/// facet observations 14, facets 15–16), stage 5 (query, rollups & search 17–20),
/// stage 6 (meta 21–22), stage 7 (attachments 23–26), stage 8 (work 27), and
/// suggestion resolution as shipping ordinal 28, followed by the
/// suggestion-review App launcher and later additive tools.
pub fn register_surface_tools(registry: &mut ToolRegistry) -> Result<()> {
    orientation::register_orientation_tools(registry)?;
    quickstart::register_quickstart_tool(registry)?;
    super::guides::register_guide_tool(registry)?;
    lifecycle::register_lifecycle_tools(registry)?;
    create_many::register_create_many_tool(registry)?;
    history::register_history_tools(registry)?;
    identity::register_identity_tools(registry)?;
    policy::register_policy_tools(registry)?;
    instructions::register_instruction_tools(registry)?;
    apps::register_history_app_tool(registry)?;
    links::register_link_tools(registry)?;
    relationships::register_relationship_tools(registry)?;
    messaging::register_messaging_tools(registry)?;
    interventions::register_intervention_tools(registry)?;
    artifacts::register_artifact_tools(registry)?;
    artifact_interactions::register_artifact_interaction_tool(registry)?;
    observations::register_observation_tools(registry)?;
    facets::register_facet_tools(registry)?;
    querying::register_query_tools(registry)?;
    resolution::register_resolution_tools(registry)?;
    meta::register_meta_tools(registry)?;
    attachments::register_attachment_tools(registry)?;
    work::register_work_tools(registry)?;
    suggestions::register_suggestion_tools(registry)?;
    apps::register_suggestion_app_tool(registry)?;
    citations::register_citation_tools(registry)?;
    attribution::register_attribution_tools(registry)?;
    change_summaries::register_change_summary_tools(registry)?;
    exploration::register_exploration_tools(registry)?;
    event_context::register_event_context_tool(registry)?;
    intent::register_intent_tool(registry)?;
    record_shape::register_record_shape_tool(registry)?;
    canvas::register_canvas_tools(registry)?;
    Ok(())
}

#[cfg(feature = "experimental-agent-intents")]
pub use experimental_agent_intents::register_experimental_agent_intent_tool;

/// Register experimental tools selected by this build without adding them to
/// the stable surface registrar or generated stable inventory.
#[doc(hidden)]
pub fn register_build_enabled_experimental_tools(_registry: &mut ToolRegistry) -> Result<()> {
    #[cfg(feature = "experimental-agent-intents")]
    experimental_agent_intents::register_experimental_agent_intent_tool(_registry)?;
    Ok(())
}

/// Register the universal snapshot capability using the transport's concrete
/// source (decision 256ceb4). Both hosted and stdio call this registrar.
pub fn register_snapshot_tool(
    registry: &mut ToolRegistry,
    snapshot_source: SnapshotSourceRef,
) -> Result<()> {
    export::register_export_tool(registry, snapshot_source)
}

/// The `reason` field's description, shared by authoring actions that require
/// durable rationale (spec fbfaf25 §3.1 and later tool decisions).
///
/// The wording is the feature. A vague prompt gets filled with a restatement of
/// the record — and the failure would then be in the QUESTION, not in the fill
/// rate, which is the trap a mandatory prose field usually falls into. So it asks
/// for the alternatives weighed and discarded and what the write argues against,
/// and says outright that restating the record is not an answer.
///
/// The line between the tools that carry it and the tools that do not is
/// **authoring versus mechanics**. A facet set is a much smaller act than
/// authoring a record; a link write is usually a consequence of an authoring act
/// that captured its reasoning one call earlier; `start_work` is a lifecycle
/// transition with no authored content; meta writes are schema mechanics.
/// Requiring prose for those produces noise, and mandatory fields attract
/// garbage. Archive and delete are in scope despite being small acts, because
/// they are the two where the reasoning is least recoverable afterwards and the
/// act is most consequential.
pub(crate) const REASON_DESCRIPTION: &str =
    "Why this change: reasoning and alternatives, including what you were arguing \
     against. Restating the record is not an answer. See the effective-writing guide.";

/// Shared response contract for direct record-write tools. Keeping the wording
/// identical makes the compensating-forward recovery path discoverable at the
/// moment an agent is deciding whether an in-place write is safe.
pub(crate) const PREVIOUS_SEQ_DESCRIPTION: &str =
    "Returns previous_seq, the pre-write record event seq. Use get_record with \
     as_of.content_seq to reconstruct prior state; see the lifecycle guide.";

/// Parse a tool's arguments into its typed shape, naming the tool in the
/// error — the message is what the caller sees, verbatim.
pub(crate) fn parse_args<T: DeserializeOwned>(tool: &str, arguments: Value) -> Result<T> {
    serde_json::from_value(arguments)
        .map_err(|err| Error::engine(format!("invalid arguments for {tool}: {err}")))
}

/// Runtime enforcement for required-reason actions. JSON Schema helps
/// contract-driven callers, but direct registry/HTTP calls still reach serde,
/// and `String` alone accepts both empty and whitespace-only garbage.
pub(crate) fn require_nonblank_reason(tool: &str, reason: &str) -> Result<()> {
    if reason.trim().is_empty() {
        return Err(Error::engine(format!(
            "{tool}: 'reason' must contain non-whitespace reasoning"
        )));
    }
    Ok(())
}

/// Highest authoritative event sequence on `record_id` before a supported
/// record-write tool appends anything in its caller-owned transaction.
///
/// This is deliberately record-scoped, not the global log head: replaying the
/// global prefix through this sequence reconstructs this record immediately
/// before the call while ignoring unrelated later events. Callers must read it
/// once and carry the value across every event in a multi-event tool call.
pub(crate) async fn previous_record_seq_in(
    tx: &mut Transaction<'static, Sqlite>,
    record_id: &str,
) -> Result<Option<i64>> {
    Ok(
        sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id = ?")
            .bind(record_id)
            .fetch_one(&mut **tx)
            .await?,
    )
}

/// Translate the transport-authenticated account token into the portable
/// policy principal. Hosted callers have already passed the live catalog
/// membership check before a database is selected; stdio callers are the
/// selected in-file account and enforcement is advisory at the filesystem
/// boundary. In both cases the dynamic `members` subject is therefore live.
pub(crate) fn principal(caller: &Caller) -> Principal<'_> {
    if is_legacy_local(caller) {
        Principal::trusted_local()
    } else {
        Principal::bound(caller.credential(), true)
    }
}

/// The one statement of who may rename the workspace.
///
/// The workspace IS `native:root`, so renaming it means writing that record's
/// `name`. Genesis grants `members -> edit` on the root so that ordinary
/// filing works, which would otherwise let any member relabel the whole
/// workspace for everybody. Relabelling it is host-owner administration, and
/// it is refused for anyone else — the same external authority that lets a
/// host owner or standalone operator administer the root policy in
/// `manage_record_policy`.
///
/// `Caller::is_host_owner()` is `hosting_database.is_none() || hosting_owner`,
/// so standalone and stdio callers pass unconditionally. That pass-through is
/// deliberate: a local file's operator boundary is filesystem possession, not
/// a catalog role, and there is no separate local carve-out to maintain.
///
/// The rule lives here rather than in any one backend's `update_record`
/// because SQLite, Postgres, and Turso-local each implement that tool
/// separately; every one of them calls this so the contract reads the same on
/// whichever storage a database happens to sit.
///
/// The refusal names the rule and nothing else: no roster, no policy entries,
/// no hint about who the owner is.
///
/// This is also the single cross-backend input contract for the display name:
/// 1-80 Unicode scalar characters, already trimmed. Ordinary record names keep
/// their broader contract; only `native:root` identifies a workspace.
pub(crate) fn require_workspace_rename_authority(
    tool: &str,
    caller: &Caller,
    record_id: &str,
    new_name: Option<&Value>,
) -> crate::error::Result<()> {
    if record_id != crate::schema::ROOT_RECORD_ID || new_name.is_none() {
        return Ok(());
    }
    if !caller.is_host_owner() {
        return Err(crate::error::Error::engine(format!(
            "{tool}: renaming the workspace ({}) is reserved to the host owner",
            crate::schema::ROOT_RECORD_ID
        )));
    }
    let Some(name) = new_name.and_then(Value::as_str) else {
        return Err(crate::error::Error::engine(format!(
            "{tool}: workspace name must be a string"
        )));
    };
    if name.is_empty() || name.trim() != name || name.chars().count() > 80 {
        return Err(crate::error::Error::engine(format!(
            "{tool}: workspace name must be 1-80 trimmed characters"
        )));
    }
    Ok(())
}

/// `Caller::local()` is the in-process/test compatibility identity predating
/// portable accounts. It represents an explicitly trusted filesystem/embedder
/// boundary, not an authenticated hosted account. Keep that legacy boundary
/// advisory while every real hosted/stdio caller is checked identically.
pub(crate) fn is_legacy_local(caller: &Caller) -> bool {
    caller.is_trusted_local() && caller.hosting_database().is_none()
}

pub(crate) async fn can_record(
    db: &crate::db::Db,
    caller: &Caller,
    record_id: &str,
    required: Capability,
) -> Result<bool> {
    // Canonical governed identity/read admission precedes ACL lookup. Besides
    // hiding attribution aggregates from ordinary tools, this keeps malformed
    // comments missing-equivalent without turning authorization into an
    // existence oracle.
    if !crate::query::read::ordinary_record_read_eligible(db, record_id).await? {
        return Ok(false);
    }
    if is_legacy_local(caller) {
        return Ok(
            authorization::validate_authorization_shape(db, record_id, true)
                .await
                .is_ok(),
        );
    }
    match authorization::effective_capability(db, principal(caller), record_id).await {
        Ok(actual) => Ok(actual.allows(required)),
        // A malformed policy state fails database open/conformance. At the
        // product surface, absence, tombstones and denial stay one answer.
        Err(_) => Ok(false),
    }
}

/// Snapshot-scoped form of [`can_record`]. Read handlers use this for every
/// authorization decision that controls data returned from the same live
/// transaction.
pub(crate) async fn can_record_in(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    record_id: &str,
    required: Capability,
) -> Result<bool> {
    if !crate::query::read::ordinary_record_read_eligible_live_in(tx, record_id).await? {
        return Ok(false);
    }
    if is_legacy_local(caller) {
        return Ok(
            authorization::validate_authorization_shape_on(tx, record_id, true)
                .await
                .is_ok(),
        );
    }
    match authorization::effective_capability_on(tx, principal(caller), record_id).await {
        Ok(actual) => Ok(actual.allows(required)),
        Err(_) => Ok(false),
    }
}

pub(crate) async fn can_record_in_pool(
    pool: &sqlx::SqlitePool,
    caller: &Caller,
    record_id: &str,
    required: Capability,
) -> Result<bool> {
    let mut snapshot = pool.begin().await?;
    let result = can_record_in(&mut snapshot, caller, record_id, required).await;
    let rollback = snapshot.rollback().await;
    match result {
        Ok(value) => {
            rollback?;
            Ok(value)
        }
        Err(error) => Err(error),
    }
}

pub(crate) async fn require_record(
    db: &crate::db::Db,
    caller: &Caller,
    tool: &str,
    record_id: &str,
    required: Capability,
) -> Result<()> {
    if !crate::query::read::ordinary_record_read_eligible(db, record_id).await? {
        return Err(record_not_found(tool, record_id));
    }
    if is_legacy_local(caller) {
        return authorization::validate_authorization_shape(db, record_id, true)
            .await
            .map_err(|_| record_not_found(tool, record_id));
    }
    match authorization::effective_capability(db, principal(caller), record_id).await {
        Ok(actual) if actual.allows(required) => Ok(()),
        Ok(actual) if actual.allows(Capability::View) => {
            Err(insufficient_capability(tool, record_id, required, actual))
        }
        // Missing records and malformed authorization remain indistinguishable
        // from records the caller cannot view.
        Ok(_) | Err(_) => Err(record_not_found(tool, record_id)),
    }
}

fn record_not_found(tool: &str, record_id: &str) -> Error {
    Error::engine(format!("{tool}: record {record_id} does not exist"))
}

fn insufficient_capability(
    tool: &str,
    record_id: &str,
    required: Capability,
    actual: Capability,
) -> Error {
    let required = required
        .as_policy_str()
        .expect("a record guard never requires the none capability");
    let actual = actual
        .as_policy_str()
        .expect("a visible record always has a named capability");
    Error::engine(format!(
        "{tool}: record {record_id} requires {required} capability; caller has {actual} capability"
    ))
}

/// Transaction-scoped authorization for protected writes. No convenience
/// preflight may substitute for this check: it shares the exact SQLite
/// snapshot and reserved write lock with the mutation.
pub(crate) async fn require_record_in(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    tool: &str,
    record_id: &str,
    required: Capability,
) -> Result<()> {
    if !crate::query::read::ordinary_record_read_eligible_live_in(tx, record_id).await? {
        return Err(record_not_found(tool, record_id));
    }
    if is_legacy_local(caller) {
        return authorization::validate_authorization_shape_on(tx, record_id, true)
            .await
            .map_err(|_| record_not_found(tool, record_id));
    }
    match authorization::effective_capability_on(tx, principal(caller), record_id).await {
        Ok(actual) if actual.allows(required) => Ok(()),
        Ok(actual) if actual.allows(Capability::View) => {
            Err(insufficient_capability(tool, record_id, required, actual))
        }
        Ok(_) | Err(_) => Err(record_not_found(tool, record_id)),
    }
}

pub(crate) async fn require_record_in_pool(
    pool: &sqlx::SqlitePool,
    caller: &Caller,
    tool: &str,
    record_id: &str,
    required: Capability,
) -> Result<()> {
    let mut snapshot = pool.begin().await?;
    let result = require_record_in(&mut snapshot, caller, tool, record_id, required).await;
    let rollback = snapshot.rollback().await;
    match result {
        Ok(()) => rollback.map_err(Into::into),
        Err(error) => Err(error),
    }
}

pub(crate) async fn visible_ids_in(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    ids: Vec<String>,
) -> Result<std::collections::HashSet<String>> {
    visible_ids_preloaded_in(tx, caller, &ids).await
}

/// Set-wise bulk visibility. Authorization itself is still the canonical
/// derived/Unit/policy/owner fold; only its relational inputs are preloaded as
/// sets. Governed comment integrity remains a separate admission rule.
pub(crate) async fn visible_ids_preloaded_in(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    ids: &[String],
) -> Result<std::collections::HashSet<String>> {
    let ids = ids
        .iter()
        .cloned()
        .collect::<std::collections::HashSet<_>>();
    if ids.is_empty() {
        return Ok(std::collections::HashSet::new());
    }
    let ids_json = serde_json::to_string(&ids)?;
    let attribution_predicate = crate::query::attribution_predicate("r");
    let comment_predicate = crate::query::comment_predicate("r");
    let admission_rows = sqlx::query(&format!(
        "SELECT r.id, ({attribution_predicate}) AS attribution, \
                ({comment_predicate}) AS comment \
           FROM records r WHERE r.id IN (SELECT value FROM json_each(?))"
    ))
    .bind(ids_json)
    .fetch_all(&mut **tx)
    .await?;
    let mut excluded = std::collections::HashSet::new();
    for row in admission_rows {
        let id: String = row.try_get("id")?;
        if row.try_get::<i64, _>("attribution")? != 0 {
            excluded.insert(id);
        } else if row.try_get::<i64, _>("comment")? != 0
            && !crate::query::read::ordinary_record_read_eligible_live_in(tx, &id).await?
        {
            // Comment integrity has its own governed validation. Keep that
            // admission step scalar while policy evaluation stays set-wise;
            // ordinary records still pay no request-scaled authorization.
            excluded.insert(id);
        }
    }
    let candidates = ids
        .iter()
        .filter(|id| !excluded.contains(*id))
        .cloned()
        .collect::<Vec<_>>();
    let visible = authorization::ids_with_capability_preloaded_on(
        tx,
        principal(caller),
        candidates,
        Capability::View,
        is_legacy_local(caller),
    )
    .await?;
    Ok(visible.into_iter().collect())
}

pub(crate) async fn visible_ids(
    db: &crate::db::Db,
    caller: &Caller,
    ids: Vec<String>,
) -> Result<std::collections::HashSet<String>> {
    let mut snapshot = db.write_pool().begin().await?;
    let result = visible_ids_in(&mut snapshot, caller, ids).await;
    let rollback = snapshot.rollback().await;
    match result {
        Ok(value) => {
            rollback?;
            Ok(value)
        }
        Err(error) => Err(error),
    }
}

pub(crate) async fn visible_ids_in_pool(
    pool: &sqlx::SqlitePool,
    caller: &Caller,
    ids: Vec<String>,
) -> Result<std::collections::HashSet<String>> {
    let mut snapshot = pool.begin().await?;
    let result = visible_ids_in(&mut snapshot, caller, ids).await;
    let rollback = snapshot.rollback().await;
    match result {
        Ok(value) => {
            rollback?;
            Ok(value)
        }
        Err(error) => Err(error),
    }
}

/// Add the write affordance to an existing structured tool result without
/// changing that tool's established top-level response shape.
pub(crate) fn echo_previous_seq(mut result: Value, previous_seq: Option<i64>) -> Result<Value> {
    let object = result
        .as_object_mut()
        .ok_or_else(|| Error::engine("record write returned a non-object result"))?;
    object.insert("previous_seq".into(), previous_seq.into());
    Ok(result)
}

#[cfg(test)]
mod bulk_visibility_tests {
    use serde_json::json;

    use super::*;
    use crate::authorization::{AllowEntry, Capability};
    use crate::schema::ROOT_RECORD_ID;
    use crate::store::AppendSpec;

    const PARENT: &str = "b71d0000-0000-4000-8000-000000000001";
    const INHERITED: &str = "b71d0000-0000-4000-8000-000000000002";
    const DENIED: &str = "b71d0000-0000-4000-8000-000000000003";
    const OWNER: &str = "b71d0000-0000-4000-8000-000000000004";
    const OWNED: &str = "b71d0000-0000-4000-8000-000000000005";
    const UNIT: &str = "b71d0000-0000-4000-8000-000000000006";
    const ATTRIBUTION: &str = "b71d0000-0000-4000-8000-000000000007";
    const MISSING: &str = "b71d0000-0000-4000-8000-000000000008";
    const INVALID_COMMENT: &str = "b71d0000-0000-4000-8000-000000000009";

    async fn create_record(db: &crate::db::Db, value: Value) {
        crate::store::create_record(db, value).await.unwrap();
    }

    #[tokio::test]
    async fn visible_ids_in_matches_scalar_admission_and_authorization() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        create_record(
            &db,
            json!({"id":PARENT,"type":"Collection","kind":"folder","name":"parent","home_id":ROOT_RECORD_ID}),
        )
        .await;
        crate::authorization::replace_explicit_policy(
            &db,
            "test:policy",
            PARENT,
            vec![AllowEntry::account("acct:viewer", Capability::View)],
        )
        .await
        .unwrap();
        create_record(
            &db,
            json!({"id":INHERITED,"type":"Document","kind":"note","name":"inherited","home_id":PARENT}),
        )
        .await;
        create_record(
            &db,
            json!({"id":DENIED,"type":"Document","kind":"note","name":"denied","home_id":ROOT_RECORD_ID}),
        )
        .await;
        crate::authorization::replace_explicit_policy(&db, "test:policy", DENIED, vec![])
            .await
            .unwrap();
        create_record(
            &db,
            json!({"id":OWNER,"type":"Entity","kind":"person","name":"owner","home_id":ROOT_RECORD_ID}),
        )
        .await;
        sqlx::query(
            "INSERT INTO bindings(record_id,system,identifier,is_canonical) \
             VALUES(?,'account','acct:viewer',1)",
        )
        .bind(OWNER)
        .execute(db.write_pool())
        .await
        .unwrap();
        create_record(
            &db,
            json!({"id":OWNED,"type":"Document","kind":"note","name":"owned","home_id":ROOT_RECORD_ID,"owner_id":OWNER}),
        )
        .await;
        crate::store::append(
            &db,
            AppendSpec {
                record_id: UNIT.into(),
                event_type: "record.created".into(),
                payload: json!({"type":"Entity","kind":"semantic-unit","name":"unit","home_id":ROOT_RECORD_ID}),
                actor: None,
            },
        )
        .await
        .unwrap();
        crate::store::append(
            &db,
            AppendSpec {
                record_id: UNIT.into(),
                event_type: "unit.created.v1".into(),
                payload: json!({
                    "semantic_contract_version":"native.freshness-kernel.v1",
                    "authority_bearer_record_id":INHERITED,
                    "label":"unit"
                }),
                actor: Some("test:unit".into()),
            },
        )
        .await
        .unwrap();
        // Attribution aggregates are never ordinary records, even when their
        // inherited policy would otherwise grant view.
        sqlx::query(
            "INSERT INTO records(id,type,kind,name,home_id,policy_anchor_id) \
             VALUES(?,'Annotation','attribution','attribution',?,?)",
        )
        .bind(ATTRIBUTION)
        .bind(PARENT)
        .bind(PARENT)
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO records(id,type,kind,name,body,home_id,policy_anchor_id) \
             VALUES(?,'Annotation','comment','invalid comment','',?,?)",
        )
        .bind(INVALID_COMMENT)
        .bind(PARENT)
        .bind(PARENT)
        .execute(db.write_pool())
        .await
        .unwrap();

        let caller = Caller::authenticated("acct:viewer");
        let ids = [
            PARENT,
            INHERITED,
            DENIED,
            OWNED,
            UNIT,
            ATTRIBUTION,
            INVALID_COMMENT,
            MISSING,
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>();
        let mut tx = db.write_pool().begin().await.unwrap();
        let mut scalar = std::collections::HashSet::new();
        for id in &ids {
            if can_record_in(&mut tx, &caller, id, Capability::View)
                .await
                .unwrap()
            {
                scalar.insert(id.clone());
            }
        }
        let batched = visible_ids_in(&mut tx, &caller, ids.clone()).await.unwrap();
        assert_eq!(batched, scalar);
        assert_eq!(
            batched,
            [PARENT, INHERITED, OWNED, UNIT]
                .into_iter()
                .map(String::from)
                .collect()
        );
        tx.rollback().await.unwrap();
        assert_eq!(visible_ids(&db, &caller, ids).await.unwrap(), scalar);
        db.close().await;
    }
}
