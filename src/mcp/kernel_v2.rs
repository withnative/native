//! Probe-only ordinary MCP tools over the v2 kernel, without the v1 schema.
mod account_config;
mod activity;
mod app_data;
mod apps;
pub(crate) mod artifacts;
#[cfg(feature = "v2-kernel-probe")]
#[allow(dead_code)] // Inactive scoped ToolRegistry proof lane.
mod current_body_read;
mod saved_tabs;
pub use app_data::NativeAppDataNeeds;
mod attachments;
mod bindings;
mod bootstrap_diagnostics;
mod canvas;
mod changes;
mod citations;
pub(crate) mod comments;
pub(crate) mod coordination;
mod deletion;
mod describe_schema;
mod event_context;
mod guidance;
mod history_diff;
pub mod identity_read;
pub(crate) mod intents;
mod interventions;
mod member_configuration;
mod merge_body;
mod messaging;
mod metadata_reads;
mod schema_config_operations;
mod schema_operations;
mod type_correction;
pub(crate) use metadata_reads::GUARANTEE as NATIVE_SCHEMA_SHAPE_GUARANTEE;
mod contracts;
#[cfg(feature = "package-cel-dev")]
mod package_operations;
mod policy;
#[cfg(test)]
mod policy_mutation_tests;
mod read_disclosures;
mod read_surface;
pub mod record_images;
mod record_reads;
pub mod reference_read;
pub mod release_append;
mod scan;
mod shape;
mod source_basis;
pub(crate) mod sql;
mod suggestions;
mod surface_bindings;
pub mod webhooks;
pub(crate) mod workspace_snapshot;
pub(crate) mod write_diagnostics;
pub(crate) mod writes;
pub(crate) use writes::render_links;

#[cfg(feature = "v2-kernel-probe")]
pub(crate) use sql::working_snapshot::{PinnedWorkingCollection, PinnedWorkingRead};

use serde::Deserialize;
use serde_json::{json, Value};

use super::registry::{Caller, EngineHandle, EngineKind, ToolRegistry};
use crate::{db::Db, kernel, Error, Result};

/// Read-only pre-spawn guard for the inactive native peer-operation unit.
#[cfg(feature = "v2-kernel-probe")]
#[allow(dead_code)]
pub(crate) fn require_no_sql_session_for_native_peer_ingress() -> Result<()> {
    sql::require_no_read_session()
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(crate) async fn with_native_peer_sql_read_session_for_test<'a, T, F>(
    db: &'a Db,
    actor: &'a str,
    reads: &'a [(&'a str, &'a str)],
    work: F,
) -> Result<T>
where
    T: 'a,
    F: std::future::Future<Output = Result<T>> + 'a,
{
    sql::with_read_session(db, actor, reads, work).await
}

pub(crate) async fn principal(db: &Db, caller: &Caller) -> Result<String> {
    // Credential is the authenticated transport identity, never a supplied
    // person id, agent label, run key or the legacy trusted-local bypass.
    let id = kernel::resolve_caller_principal_by_binding(db, caller.credential())
        .await?
        .map(|(id, _, _)| id)
        .ok_or_else(|| Error::engine("kernel-v2: caller has no principal auth_binding"))?;
    let mut snapshot = db.pool().begin().await?;
    let admitted = kernel::hosted_identity::admitted(&mut snapshot, &id).await?;
    snapshot.rollback().await?;
    if !admitted {
        return Err(Error::engine("database membership not found"));
    }
    if let Some(key) = caller.run_key().filter(|key| *key != "new") {
        kernel::run_ledger::reject_historical_key_as(db, key).await?;
    }
    Ok(id)
}

/// Recheck ordinary transport authority on the actual write transaction.
/// Ordinary principals need not be account contributors; live CRDT authors
/// are admitted separately by the coedit adapter when minting a candidate.
pub(crate) async fn principal_on(
    conn: &mut sqlx::SqliteConnection,
    caller: &Caller,
) -> Result<String> {
    if caller.credential().starts_with("host:") {
        return Err(Error::engine(
            "kernel-v2: host bindings cannot authenticate callers",
        ));
    }
    let id: String =
        sqlx::query_scalar("SELECT principal_id FROM kernel_principals WHERE auth_binding=?")
            .bind(caller.credential())
            .fetch_optional(&mut *conn)
            .await?
            .ok_or_else(|| Error::engine("kernel-v2: caller has no principal auth_binding"))?;
    if !kernel::hosted_identity::admitted(conn, &id).await? {
        return Err(Error::engine("database membership not found"));
    }
    if let Some(app) = caller.host_asserted_app() {
        kernel::app_installs::admit_app_on(conn, &id, app).await?;
    }
    if let Some(key) = caller.run_key().filter(|key| *key != "new") {
        kernel::run_ledger::reject_historical_key_on(conn, key).await?;
    }
    Ok(id)
}

// Tests can suspend one actual registered read after its handler finishes,
// before the final authority check. This is task-local, never a global hook.
#[cfg(test)]
tokio::task_local! {
    static READ_RETURN_BARRIER: (std::sync::Arc<tokio::sync::Notify>, std::sync::Arc<tokio::sync::Notify>);
}

#[cfg(test)]
pub(crate) async fn with_read_return_barrier<F: std::future::Future>(
    entered: std::sync::Arc<tokio::sync::Notify>,
    resume: std::sync::Arc<tokio::sync::Notify>,
    work: F,
) -> F::Output {
    READ_RETURN_BARRIER.scope((entered, resume), work).await
}

#[cfg(test)]
async fn pause_before_read_return() {
    if let Ok((entered, resume)) = READ_RETURN_BARRIER.try_with(Clone::clone) {
        entered.notify_one();
        resume.notified().await;
    }
}

/// Register hosted v2 handlers without changing the v1 discovery schemas.
/// The local probe registrar retains its historical single-engine projection.
pub fn register_hosted_kernel_v2_tools(registry: &mut ToolRegistry) -> Result<()> {
    let originals = ["get_history", "start_work"]
        .into_iter()
        .map(|name| {
            let schema = registry
                .get(name)
                .ok_or_else(|| Error::engine("missing KernelV2 tool descriptor"))?
                .input_schema
                .clone();
            Ok((name, schema))
        })
        .collect::<Result<Vec<_>>>()?;
    register_kernel_v2_tools(registry)?;
    for (name, original) in originals {
        registry.isolate_kernel_v2_schema(name, original)?;
    }
    Ok(())
}

/// Install alternate handlers on the ordinary tool descriptors.
pub fn register_kernel_v2_tools(registry: &mut ToolRegistry) -> Result<()> {
    #[cfg(feature = "package-cel-dev")]
    package_operations::register(registry)?;
    apps::register(registry)?;
    register_app_bundle(registry)?;
    intents::register(registry)?;
    deletion::register(registry)?;
    citations::register(registry)?;
    type_correction::register(registry)?;
    bindings::register(registry)?;
    interventions::register(registry)?;
    macro_rules! register {
        ($name:literal, $handler:path) => {
            registry.register_engine_handler(
                $name,
                EngineKind::KernelV2,
                |engine, caller, arguments| async move {
                    let EngineHandle::KernelV2(db) = engine else {
                        unreachable!()
                    };
                    let actor = principal(&db, &caller).await?;
                    let attachment_mutation =
                        $name == "manage_attachments" && arguments["action"] == "detach";
                    let value = $handler(&db, &actor, arguments).await?;
                    #[cfg(test)]
                    if $name == "whats_changed" {
                        pause_before_read_return().await;
                    }
                    // Composed reads can use several separately authorized
                    // snapshots. Refuse a changed consent/source before
                    // returning their result; writes never get a fallible
                    // post-commit check that could hide committed success.
                    if matches!(
                        $name,
                        "render_artifact"
                            | "read_canvas"
                            | "get_record"
                            | "query_record"
                            | "whats_changed"
                            | "query_sql"
                            | "get_history"
                            | "search"
                            | "read_attachment"
                            | "manage_attachments"
                            | "get_structure"
                            | "open_collection"
                            | "resolve_facets"
                            | "suggest_facet_values"
                            | "get_run_activity"
                            | "preview_record_shape"
                            | "get_event_context"
                            | "get_dashboard"
                            | "scan"
                            | "render_record"
                            | "resolve_many"
                            | "render_record_version_diff"
                    ) && !attachment_mutation
                    {
                        if let Some(app) = caller.host_asserted_app() {
                            kernel::app_installs::admit_account_app_as(
                                &db,
                                caller.credential(),
                                app,
                            )
                            .await?;
                        }
                    }
                    Ok(value)
                },
            )?;
        };
    }
    register!("read_canvas", canvas::read);
    register!("manage_canvas", canvas::manage);
    register!("manage_participants", messaging::participants);
    registry.register_engine_handler(
        "manage_messages",
        EngineKind::KernelV2,
        |engine, caller, args| async move {
            let EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            crate::mcp::tools::messaging::validate_kernel_arguments(&args)?;
            if args["action"] == "set_agent_disposition"
                && caller.verified_agent_executor().is_none()
            {
                return Err(crate::mcp::tools::messaging::authority_refusal(
                    "agent disposition requires server-verified executor and delegation context",
                ));
            }
            if args["action"] == "mutate_human_awareness"
                && caller.verified_human_interaction().is_none()
            {
                return Err(crate::mcp::tools::messaging::authority_refusal(
                    "human awareness requires a server-verified interaction attestation",
                ));
            }
            if args["action"] == "set_routing"
                && caller.verified_human_interaction().is_none()
                && !caller.has_policy_authority()
            {
                return Err(crate::mcp::tools::messaging::authority_refusal(
                    "routing requires attested principal choice or trusted policy authority",
                ));
            }
            let actor = principal(&db, &caller).await?;
            messaging::execute(&db, &actor, &caller, args).await
        },
    )?;
    register!("read_attachment", attachments::read);
    register!("manage_attachments", attachments::manage);
    registry.set_kernel_v2_schema("manage_attachments", json!({"oneOf":[
        {"type":"object","properties":{"action":{"const":"list"},"record_id":{"type":"string"}},"required":["action","record_id"],"additionalProperties":false},
        {"type":"object","properties":{"action":{"const":"inspect"},"attachment_id":{"type":"string"}},"required":["action","attachment_id"],"additionalProperties":false},
        {"type":"object","properties":{"action":{"const":"detach"},"attachment_id":{"type":"string"},"if_content_seq":{"type":"integer","description":"Optional expected attachment revision; a mismatch appends nothing."}},"required":["action","attachment_id"],"additionalProperties":false}
    ]}))?;
    registry.register_engine_handler(
        "get_record",
        EngineKind::KernelV2,
        |engine, caller, args| async move {
            let EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            #[cfg(all(test, feature = "v2-kernel-probe"))]
            if current_body_read::selected() {
                return current_body_read::get(&db, &caller, args).await;
            }
            let actor = principal(&db, &caller).await?;
            let value = get_record(&db, &actor, args).await?;
            if let Some(app) = caller.host_asserted_app() {
                kernel::app_installs::admit_account_app_as(&db, caller.credential(), app).await?;
            }
            Ok(value)
        },
    )?;
    register!("resolve_many", record_reads::resolve_many);
    register!("render_record", record_reads::render_record);
    register!("get_dashboard", record_reads::get_dashboard);
    register!("scan", scan::scan);
    register!("get_structure", read_surface::get_structure);
    register!("open_collection", read_surface::open_collection);
    register!("resolve_facets", metadata_reads::resolve_facets);
    register!("suggest_facet_values", metadata_reads::suggest);
    schema_operations::register(registry)?;
    schema_config_operations::register(registry)?;
    register!("query_record", query_record);
    register!("get_history", get_history);
    register!("get_run_activity", activity::read);
    register!("preview_record_shape", shape::preview);
    register!("get_event_context", event_context::get);
    register!("render_record_version_diff", history_diff::render);
    register!("whats_changed", changes::whats_changed);
    registry.register_engine_handler(
        "get_workspace_snapshot",
        EngineKind::KernelV2,
        |engine, caller, arguments| async move {
            let EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            principal(&db, &caller).await?;
            let result = crate::mcp::tools::workspace_snapshot::get_workspace_snapshot(
                db.clone(),
                caller.clone(),
                arguments,
            )
            .await?;
            if let Some(app) = caller.host_asserted_app() {
                kernel::app_installs::admit_account_app_as(&db, caller.credential(), app).await?;
            }
            Ok(result)
        },
    )?;
    registry.extend_kernel_v2_arguments("get_history", json!({"include_import_receipts": {
        "type":"boolean", "default":false,
        "description":"KernelV2 migration detail: include attributed import receipts, omitted from ordinary history."
    }}))?;
    register!("search", search);
    let artifact_delivery = registry.app_bundle_delivery();
    registry.register_engine_handler(
        "render_artifact",
        EngineKind::KernelV2,
        move |engine, caller, arguments| {
            let delivery = artifact_delivery.clone();
            async move {
                let EngineHandle::KernelV2(db) = engine else {
                    unreachable!()
                };
                let actor = principal(&db, &caller).await?;
                let value = match artifacts::html_board::try_render(
                    &db,
                    &caller,
                    &actor,
                    &arguments,
                    delivery.as_ref(),
                )
                .await?
                {
                    Some(value) => value,
                    None => {
                        artifacts::render_with_database(
                            &db,
                            &actor,
                            caller.hosting_database(),
                            arguments,
                        )
                        .await?
                    }
                };
                if let Some(app) = caller.host_asserted_app() {
                    kernel::app_installs::admit_account_app_as(&db, caller.credential(), app)
                        .await?;
                }
                Ok(value)
            }
        },
    )?;
    guidance::register(registry)?;
    describe_schema::register(registry)?;
    coordination::register(registry)?;
    member_configuration::register(registry)?;
    surface_bindings::register(registry)?;
    registry.register_engine_handler(
        "query_sql",
        EngineKind::KernelV2,
        |engine, caller, args| async move {
            let EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            let actor = principal(&db, &caller).await?;
            let value = sql::query_sql_for_caller(&db, &actor, &caller, args).await?;
            if let Some(app) = caller.host_asserted_app() {
                kernel::app_installs::admit_account_app_as(&db, caller.credential(), app).await?;
            }
            Ok(value)
        },
    )?;
    policy::register(registry)?;
    account_config::register(registry)?;
    saved_tabs::register(registry)?;
    writes::register(registry)?;
    contracts::register(registry)?;
    merge_body::register(registry)?;
    registry.register_engine_handler(
        "resolve_suggestions",
        EngineKind::KernelV2,
        |engine, caller, args| async move {
            let EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            let actor = principal(&db, &caller).await?;
            if let Some(result) =
                crate::mcp::tools::hcp_v2::kernel_human::resolve(&db, &caller, &actor, &args)
                    .await?
            {
                return Ok(result);
            }
            suggestions::resolve(&db, &actor, args).await
        },
    )?;
    Ok(())
}

fn register_app_bundle(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_engine_handler(
        "read_app_bundle",
        EngineKind::KernelV2,
        |engine, caller, arguments| async move {
            let EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            super::tools::app_bundle::refuse_app(&caller)?;
            let args = super::tools::app_bundle::Args::parse(arguments)?;
            let mut snapshot = db.pool().begin().await?;
            let actor = principal_on(&mut snapshot, &caller).await?;
            let admitted = kernel::app_installs::admit_install_on(
                &mut snapshot,
                &actor,
                &args.package,
                &args.expected_install_event_id,
            )
            .await?;
            let result = super::tools::app_bundle::response(
                args,
                admitted.body,
                admitted.pin["artifact_id"]
                    .as_str()
                    .ok_or_else(|| {
                        Error::engine(
                            "read_app_bundle: missing artifact identity [invalid_install]",
                        )
                    })?
                    .to_owned(),
                admitted.version,
                admitted.body_limit,
                db.open_mode() == crate::db::DatabaseOpenMode::StandbyReadOnly
                    || caller.hosting_database().is_none(),
            )?;
            snapshot.rollback().await?;
            Ok(result)
        },
    )
}

fn parse<T: serde::de::DeserializeOwned>(tool: &str, value: Value) -> Result<T> {
    serde_json::from_value(value).map_err(|e| {
        Error::engine(format!(
            "{tool} (kernel-v2): unsupported or invalid arguments: {e}"
        ))
    })
}
pub(crate) const LEGACY_RECEIPT_MAPPING: (&str, &str) = ("receipt.committed.v1", "record.updated");
pub(crate) const LOGICAL_EVENT_TYPES: &[(&str, &str)] = &[
    ("kernel.record_created.v1", "record.created"),
    ("kernel.record_created.v2", "record.created"),
    ("kernel.record_revised.v1", "record.updated"),
    ("kernel.record_revised.v2", "record.updated"),
    (
        "kernel.record_type_corrected.v1",
        "record.type_corrected.v1",
    ),
    ("kernel.body_set.v1", "record.updated"),
    ("kernel.metadata_set.v1", "record.updated"),
    ("kernel.archive_changed.v1", "record.updated"),
    ("kernel.record_rehomed.v1", "record.updated"),
    ("kernel.generic_link_added.v1", "link.added"),
    ("kernel.generic_link_removed.v1", "link.removed"),
    ("kernel.link_added.v1", "link.added"),
    ("kernel.link_added.v2", "link.added"),
    ("kernel.link_removed.v1", "link.removed"),
    ("kernel.comment_anchor_set.v1", "annotation.target.set"),
    (
        "kernel.comment_anchor_removed.v1",
        "annotation.target.removed",
    ),
    ("kernel.record_deleted.v1", "record.deleted"),
];
pub(crate) const IMPORTED_EVENTS: &[&str] = &[
    "kernel.generic_link_imported.v1",
    "kernel.generic_link_removal_imported.v1",
    "kernel.comment_anchor_imported.v1",
    "kernel.comment_anchor_removal_imported.v1",
];
pub(crate) fn logical_event_type(native: &str) -> &str {
    LOGICAL_EVENT_TYPES
        .iter()
        .find(|(event, _)| *event == native)
        .map_or(native, |(_, logical)| *logical)
}
fn migration_event(event: &kernel::KernelHistoryEvent) -> bool {
    event.event_type.starts_with("kernel.import_")
        || IMPORTED_EVENTS.contains(&event.event_type.as_str())
        || (event.event_type == "kernel.legacy_recorded.v1" && event.retained_legacy.is_none())
}

fn unsupported(tool: &str, what: &str) -> Error {
    Error::engine(format!("{tool} (kernel-v2): unsupported {what}"))
}

pub use crate::v2_standard::v1_compat::v1_type_and_kind;

// Ordinary records keep their v1 field names. Unmapped v2 fields remain in
// `fields`, rather than overwriting envelope keys or inventing v1 facets.
async fn record_value(db: &Db, actor: &str, record: &kernel::KernelRecordView) -> Result<Value> {
    let actor_owned = actor.to_owned();
    let record = record.clone();
    sql::in_snapshot(db, actor, move |conn| {
        Box::pin(async move { record_value_on(conn, &actor_owned, &record).await })
    })
    .await
}
async fn record_value_on(
    snapshot: &mut sqlx::SqliteConnection,
    actor: &str,
    record: &kernel::KernelRecordView,
) -> Result<Value> {
    record_value_projection_on(snapshot, actor, record, ValueProjection::Full).await
}

/// Hydration width for one record value. `Metadata` is the public
/// metadata-only response and never changes shape here; `Envelope` is the
/// private collection-envelope width — the same body-free row plus the
/// persistence already present on the view, so the envelope pairs maturity
/// and persistence from a single snapshot instead of refetching.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ValueProjection {
    Full,
    Metadata,
    Envelope,
}

async fn record_value_projection_on(
    snapshot: &mut sqlx::SqliteConnection,
    actor: &str,
    record: &kernel::KernelRecordView,
    projection: ValueProjection,
) -> Result<Value> {
    kernel::app_installs::admit_dispatched_on(snapshot, actor).await?;
    kernel::kernel_require(
        snapshot,
        actor,
        &record.id,
        crate::authorization::Capability::View,
    )
    .await?;
    let (primary_type, created_at): (Option<String>, String) =
        sqlx::query_as("SELECT primary_type, created_at FROM kernel_records WHERE id = ?")
            .bind(&record.id)
            .fetch_one(&mut *snapshot)
            .await?;
    let (record_type, kind) = v1_type_and_kind(
        record.family.as_deref(),
        record.pin.as_ref().map(|pin| pin.version),
        primary_type.as_deref(),
        record.kind.as_deref(),
        &record.fields,
    );
    let native_created_at = created_at.clone();
    let created_at = sqlx::query_scalar::<_,String>("SELECT created_at FROM kernel_legacy_sql_events WHERE record_id=? AND source_stream='snapshot_provenance' AND seq<=? ORDER BY seq DESC LIMIT 1")
        .bind(&record.id).bind(record.revision).fetch_optional(&mut *snapshot).await?.unwrap_or(created_at);
    let field = |name: &str| record.fields.get(name).cloned().unwrap_or(Value::Null);
    let updated_at: String = sqlx::query_scalar(
        "SELECT created_at FROM main.content_events WHERE record_id=? AND seq=?",
    )
    .bind(&record.id)
    .bind(record.revision)
    .fetch_one(&mut *snapshot)
    .await?;
    let body = if projection == ValueProjection::Full {
        let hydrated = record
            .body
            .as_ref()
            .map(|body| json!(body))
            .unwrap_or_else(|| field("body"));
        // Tally real body bytes materialized into full values; the envelope
        // regression compares this against the body-free paths.
        #[cfg(test)]
        read_surface::envelope_diagnostics::note_body_hydrated(
            hydrated.as_str().map(str::len).unwrap_or(0),
        );
        hydrated
    } else {
        Value::Null
    };
    let mut owner = record.owner_id.clone();
    let communication_origin =
        if projection == ValueProjection::Full && record_type == Some("Message") {
            owner = messaging::visible_person(snapshot, actor, owner.as_deref()).await?;
            let origin = if let Some(state) = kernel::messaging::on(snapshot, &record.id).await? {
                Some(kernel::messaging::communication_origin(snapshot, &state).await?)
            } else {
                None
            };
            origin
        } else {
            None
        };
    let placement_started = std::time::Instant::now();
    let home_id = crate::v1_import::placement_on(snapshot, actor, &record.id)
        .await?
        .and_then(|p| p.home_id);
    tracing::debug!(target:"native_ce::read_staging",phase="record_placement",elapsed_us=placement_started.elapsed().as_micros() as u64);
    let started = std::time::Instant::now();
    let lifecycle_interpretation = kernel::v1_state::lifecycle_on(
        snapshot,
        actor,
        record_type.unwrap_or_default(),
        kind,
        &record.id,
        record.fields.get("lifecycle").and_then(Value::as_str),
    )
    .await?;
    tracing::debug!(target:"native_ce::read_staging",phase="record_lifecycle",elapsed_us=started.elapsed().as_micros() as u64);
    if projection != ValueProjection::Full {
        // `Metadata` is the public shape and stays fixed; `Envelope` carries
        // the same row plus the persistence already on this view, so the
        // envelope never pairs maturity from one snapshot with persistence
        // refetched from another.
        let mut value = json!({
            "id":record.id,"type":record_type,"kind":kind,
            "name":record.fields.get("title").cloned().unwrap_or_else(|| field("name")),
            "summary":field("summary"),"home_id":home_id,
            "lifecycle_interpretation":lifecycle_interpretation,
            "maturity":record.metadata.maturity,"updated_at":updated_at,
            "last_activity_at":record.metadata.last_activity_at
        });
        if projection == ValueProjection::Envelope {
            value["persistence"] = json!(record.metadata.persistence);
        }
        return Ok(value);
    }
    let started = std::time::Instant::now();
    let historical_claims = kernel::v1_state::claims_on(snapshot, actor, &record.id).await?;
    tracing::debug!(target:"native_ce::read_staging",phase="record_claims",elapsed_us=started.elapsed().as_micros() as u64);
    let started = std::time::Instant::now();
    let legacy_provenance =
        crate::v1_import::legacy_record_provenance_on(snapshot, actor, &record.id).await?;
    tracing::debug!(target:"native_ce::read_staging",phase="record_provenance",elapsed_us=started.elapsed().as_micros() as u64);
    let intake = webhooks::recorded_source_on(snapshot, &record.id, record.revision).await?;
    let mut contribution = Value::Null;
    if let Some((source, act, created)) = &intake {
        let body_revision:Option<(String,String,i64)>=sqlx::query_as("SELECT id,type,act FROM main.content_events WHERE record_id=? AND seq<=? AND (type IN ('kernel.record_created.v1','kernel.record_created.v2','kernel.body_set.v1') OR (type IN ('kernel.record_revised.v1','kernel.record_revised.v2') AND json_type(payload,'$.fields.body') IS NOT NULL)) ORDER BY seq DESC LIMIT 1")
            .bind(&record.id).bind(record.revision).fetch_optional(&mut *snapshot).await?;
        if let Some((event, kind, body_act)) =
            body_revision.filter(|(_, _, body_act)| body_act == act)
        {
            let _ = body_act;
            contribution = webhooks::contribution(source, created, &event, &kind);
        }
    }
    let intake_origin = intake.map(|(source, _, _)| source);
    Ok(json!({
        "intake_origin":intake_origin,
        "contribution":contribution,
        "communication_origin":communication_origin,
        "id": record.id, "type": record_type, "kind": kind,
        "name": record.fields.get("title").cloned().unwrap_or_else(|| field("name")), "body": body, "body_digest": super::tools::lifecycle::body_digest(body.as_str()), "summary": field("summary"),
        "lifecycle": field("lifecycle"), "archived": record.archived,
        "lifecycle_interpretation":lifecycle_interpretation,
        "historical_claims":historical_claims,
        "home_id": home_id, "owner_id": owner,
        "persistence": record.metadata.persistence, "maturity": record.metadata.maturity,
        "created_at": created_at, "updated_at": updated_at, "last_activity_at": record.metadata.last_activity_at,
        "legacy_provenance": legacy_provenance,
        "deleted_at": null,
        "fields": record.fields, "version": format!("rec:{}", record.revision), "record_version": format!("rec:{}", record.revision),
        "kernel_v2": native_record_identity(record, &native_created_at)
    }))
}

pub(crate) fn native_record_identity(
    record: &kernel::KernelRecordView,
    native_created_at: &str,
) -> Value {
    json!({"family":record.family,"pin":record.pin,"interpreter":record.interpreter,"native_created_at":native_created_at})
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetArgs {
    ids: Vec<String>,
    resolve: Option<bool>,
    links_limit: Option<usize>,
    links_offset: Option<usize>,
    include_comments: Option<bool>,
    comments_limit: Option<usize>,
    comments_offset: Option<usize>,
    children_limit: Option<i64>,
    children_offset: Option<i64>,
    include_citations: Option<bool>,
    include_suggestions: Option<bool>,
    suggestions_limit: Option<i64>,
    suggestions_offset: Option<i64>,
    citations_limit: Option<i64>,
    citations_offset: Option<i64>,
    include_history_summary: Option<bool>,
}
async fn get_record(db: &Db, actor: &str, args: Value) -> Result<Value> {
    // V1 caps the batch at 100 and returns an error for a failed batch rather
    // than a successful prefix (lifecycle.rs:get_record_from_lens). Preserve
    // that shape, with an additional wall bound over staging AND hydration.
    tokio::time::timeout(get_batch_deadline(), kernel::read_cache::with_capabilities(get_record_read(db, actor, args)))
        .await.map_err(|_| Error::engine("get_record: batch deadline exceeded; no partial results returned; retry with fewer ids"))?
}
const GET_BATCH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(test)]
tokio::task_local! { static GET_BATCH_DEADLINE_OVERRIDE: std::time::Duration; }
fn get_batch_deadline() -> std::time::Duration {
    #[cfg(test)]
    if let Ok(deadline) = GET_BATCH_DEADLINE_OVERRIDE.try_with(|d| *d) {
        return deadline;
    }
    GET_BATCH_DEADLINE
}
#[inline(never)]
fn app_scope_get_precheck<'a>(
    db: &'a Db,
    actor: &'a str,
    ids: &'a [String],
) -> futures::future::BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let mut snapshot = db.write_pool().begin().await?;
        kernel::app_installs::admit_dispatched_on(&mut snapshot, actor).await?;
        for id in ids {
            if let Some(error) = kernel::app_scope_direct_refusal_on(
                &mut snapshot,
                actor,
                id,
                crate::authorization::Capability::View,
            )
            .await?
            {
                return Err(error);
            }
        }
        snapshot.rollback().await?;
        Ok(())
    })
}

const GET_RECORD_READS: &[(&str, &str)] = &[
    ("records", "id"),
    ("records", "type"),
    ("records", "kind"),
    ("records", "name"),
    ("records", "archived"),
    ("records", "created_at"),
    ("records", "home_id"),
    ("links", "source_id"),
    ("links", "target_id"),
    ("links", "relationship"),
];

async fn get_record_read(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let plan = get_plan(args)?;
    let ids = plan.args.ids.clone();
    // Direct reach by a scoped app for a person-visible record outside
    // its grant is a typed refusal, not a silent omission. Short
    // references that do not literally name a record stay omissions.
    if crate::provenance::current_app_package().is_some() {
        app_scope_get_precheck(db, actor, &ids).await?;
    }
    sql::with_part_of_read_session(
        db,
        actor,
        GET_RECORD_READS,
        &ids,
        get_record_from_plan(db, actor, plan),
    )
    .await
}
struct GetPlan {
    args: GetArgs,
    opts: crate::query::read::EnrichOptions,
    links_limit: usize,
    links_offset: usize,
    include_comments: bool,
    comments_limit: usize,
    comments_offset: usize,
}
fn get_plan(args: Value) -> Result<GetPlan> {
    let args: GetArgs = parse("get_record", args)?;
    let defaults = crate::query::read::EnrichOptions::default();
    let opts = crate::query::read::EnrichOptions {
        children_limit: args.children_limit.unwrap_or(defaults.children_limit),
        children_offset: args.children_offset.unwrap_or(0),
        links_limit: args.links_limit.unwrap_or(defaults.links_limit as usize) as i64,
        links_offset: args.links_offset.unwrap_or(0) as i64,
        link_summaries: false,
        include_suggestions: args.include_suggestions.unwrap_or(false),
        suggestions_limit: args.suggestions_limit.unwrap_or(defaults.suggestions_limit),
        suggestions_offset: args.suggestions_offset.unwrap_or(0),
        include_citations: args.include_citations.unwrap_or(false),
        citations_limit: args.citations_limit.unwrap_or(defaults.citations_limit),
        citations_offset: args.citations_offset.unwrap_or(0),
        include_comments: args.include_comments.unwrap_or(false),
        comments_limit: args
            .comments_limit
            .unwrap_or(defaults.comments_limit as usize) as i64,
        comments_offset: args.comments_offset.unwrap_or(0) as i64,
    };
    opts.validate()?;
    if args.ids.is_empty() || args.ids.len() > super::tools::lifecycle::MAX_BATCH_GET {
        return Err(Error::engine(format!(
            "get_record: ids must contain between 1 and {} records",
            super::tools::lifecycle::MAX_BATCH_GET
        )));
    }
    if args.resolve == Some(true) {
        return Err(unsupported(
            "get_record",
            "resolve=true; v1 vocabulary resolution is unavailable",
        ));
    }
    let links_limit = args
        .links_limit
        .unwrap_or(crate::query::read::DEFAULT_ENRICH_LIMIT as usize);
    let links_offset = args.links_offset.unwrap_or(0);
    if links_limit > crate::query::read::MAX_ENRICH_LIMIT as usize {
        return Err(Error::engine(
            "get_record: links_limit must be between 0 and 1000",
        ));
    }
    let include_comments = args.include_comments.unwrap_or(false);
    let comments_limit = args.comments_limit.unwrap_or(50);
    let comments_offset = args.comments_offset.unwrap_or(0);
    if comments_limit > 100 {
        return Err(Error::engine(
            "get_record: comments_limit must be between 0 and 100 (page with comments_offset)",
        ));
    }
    Ok(GetPlan {
        args,
        opts,
        links_limit,
        links_offset,
        include_comments,
        comments_limit,
        comments_offset,
    })
}
#[cfg(test)]
async fn get_record_in_session(db: &Db, actor: &str, args: Value) -> Result<Value> {
    get_record_from_plan(db, actor, get_plan(args)?).await
}
async fn get_record_from_plan(db: &Db, actor: &str, plan: GetPlan) -> Result<Value> {
    get_record_from_shared_plan(db, actor, std::sync::Arc::new(plan)).await
}
async fn get_record_from_shared_plan(
    db: &Db,
    actor: &str,
    plan: std::sync::Arc<GetPlan>,
) -> Result<Value> {
    get_record_from_shared_plan_bounded(db, actor, plan, None).await
}
async fn get_record_from_shared_plan_bounded(
    db: &Db,
    actor: &str,
    plan: std::sync::Arc<GetPlan>,
    encoded_limit: Option<usize>,
) -> Result<Value> {
    #[cfg(feature = "v2-kernel-probe")]
    let mut staged_encoded_bytes = br#"{"records":[]}"#.len();
    #[cfg(not(feature = "v2-kernel-probe"))]
    let _ = encoded_limit;
    let started = std::time::Instant::now();
    let artifact_kinds = read_surface::artifact_kinds(db, actor).await?;
    tracing::debug!(target:"native_ce::read_staging",phase="get_artifact_kinds",elapsed_us=started.elapsed().as_micros() as u64);
    let started = std::time::Instant::now();
    let artifact_counts =
        read_surface::artifact_counts(db, actor, &plan.args.ids, &artifact_kinds).await?;
    tracing::debug!(target:"native_ce::read_staging",phase="get_artifact_counts",elapsed_us=started.elapsed().as_micros() as u64);
    let started = std::time::Instant::now();
    let child_sections =
        read_surface::child_sections(db, actor, &plan.args.ids, &plan.opts).await?;
    tracing::debug!(target:"native_ce::read_staging",phase="get_child_sections",elapsed_us=started.elapsed().as_micros() as u64);
    let history_summary = plan.args.include_history_summary.unwrap_or(false);
    let actor_owned = actor.to_owned();
    let ids = plan.args.ids.clone();
    let started = std::time::Instant::now();
    let links = sql::in_snapshot(db, actor, move |conn| {
        Box::pin(async move {
            kernel::generic_links::visible_link_rows_for_on(conn, &actor_owned, &ids).await
        })
    })
    .await?;
    tracing::debug!(target:"native_ce::read_staging",phase="get_link_batch",elapsed_us=started.elapsed().as_micros() as u64);
    let mut records = Vec::with_capacity(plan.args.ids.len());
    // Partition the admitted batch once. Scanning every link again for each
    // ID made a large Get quadratic even though its SQL reads were bounded.
    let requested: std::collections::BTreeSet<_> =
        plan.args.ids.iter().map(String::as_str).collect();
    let mut by_record = std::collections::BTreeMap::<String, Vec<Value>>::new();
    for link in links {
        let source = link["source_id"].as_str();
        let target = link["target_id"].as_str();
        if let Some(source) = source.filter(|id| requested.contains(id)) {
            by_record
                .entry(source.to_owned())
                .or_default()
                .push(link.clone());
        }
        if let Some(target) = target.filter(|id| Some(*id) != source && requested.contains(id)) {
            by_record
                .entry(target.to_owned())
                .or_default()
                .push(link.clone());
        }
    }
    let links = std::sync::Arc::new(by_record);
    for id in &plan.args.ids {
        let actor_owned = actor.to_owned();
        let id_owned = id.clone();
        let plan_ref = plan.clone();
        let links_ref = links.clone();
        // Connection-scoped hydration and composed SQL consume the same
        // read snapshot; no pool transactions can observe a newer revision.
        let hydrated = sql::in_snapshot(db, actor, move |conn| {
            Box::pin(async move {
                let links = links_ref.get(&id_owned).map(Vec::as_slice).unwrap_or(&[]);
                hydrate_get_on(conn, &actor_owned, &id_owned, &plan_ref, links).await
            })
        })
        .await?;
        let mut value = if let Some(value) = hydrated {
            value
        } else if let Some(mut value) = read_surface::root(db, actor, id).await? {
            value["facets"] = json!([]);
            for field in ["links_out", "links_in"] {
                value[field] = json!([]);
                value[format!("{field}_count")] = json!(0);
            }
            value["comment_count"] = json!(0);
            if plan.include_comments {
                value["comments"] = json!([]);
            }
            value
        } else {
            let value = json!({"id":id,"status":"not_found"});
            #[cfg(feature = "v2-kernel-probe")]
            if let Some(limit) = encoded_limit {
                let remaining =
                    limit.saturating_sub(staged_encoded_bytes + usize::from(!records.is_empty()));
                staged_encoded_bytes += current_body_read::encoded_size_within(&value, remaining)?
                    + usize::from(!records.is_empty());
            }
            records.push(value);
            continue;
        };
        read_surface::enrich(
            db,
            actor,
            id,
            &plan.opts,
            &artifact_kinds,
            history_summary,
            artifact_counts.get(id).unwrap_or(&[0, 0]),
            child_sections.get(id),
            &mut value,
        )
        .await?;
        #[cfg(feature = "v2-kernel-probe")]
        if let Some(limit) = encoded_limit {
            let remaining =
                limit.saturating_sub(staged_encoded_bytes + usize::from(!records.is_empty()));
            staged_encoded_bytes += current_body_read::encoded_size_within(&value, remaining)?
                + usize::from(!records.is_empty());
        }
        records.push(value);
    }
    Ok(json!({"records": records}))
}

async fn hydrate_get_on(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    id: &str,
    plan: &GetPlan,
    links: &[Value],
) -> Result<Option<Value>> {
    let links_limit = plan.links_limit;
    let links_offset = plan.links_offset;
    let include_comments = plan.include_comments;
    let comments_limit = plan.comments_limit;
    let comments_offset = plan.comments_offset;
    if let Some(record) = kernel::read_record_on(conn, actor, id).await? {
        let value_started = std::time::Instant::now();
        let mut value = record_value_on(conn, actor, &record).await?;
        tracing::debug!(target:"native_ce::read_staging",phase="record_value",elapsed_us=value_started.elapsed().as_micros() as u64);
        value["status"] = json!("found");
        // v1 EnrichedRecord always includes facets. Keep its wire shape;
        // observation timestamps/numeric indexes are kernel internals.
        let tx = &mut *conn;
        kernel::app_installs::admit_dispatched_on(&mut *tx, actor).await?;
        kernel::kernel_require(
            &mut *tx,
            actor,
            &record.id,
            crate::authorization::Capability::View,
        )
        .await?;
        let rows: Vec<(String, Option<String>, Option<String>, i64)> = sqlx::query_as(
                "SELECT key,value,vocab_ref,event_seq FROM kernel_facets WHERE record_id=? AND value IS NOT NULL AND key!='archived' ORDER BY key"
            ).bind(&record.id).fetch_all(&mut *tx).await?;
        value["facets"] = json!(rows
            .into_iter()
            .map(
                |(key, value, vocab_ref, event_seq)| crate::query::FacetValueRow {
                    key,
                    value: value.map(Value::String),
                    vocab_ref,
                    version: Some(
                        native_artifact_runtime::artifact_intents::FacetVersion::Observation {
                            event_seq
                        }
                        .encode()
                    ),
                }
            )
            .collect::<Vec<_>>());
        if value["type"] == "Message" {
            if let Some(state) = kernel::messaging::on(&mut *tx, &record.id).await? {
                if let Some(speaker) = &state.speaker {
                    value["speaker"] = speaker.clone();
                }
                value["mentions"] = messaging::mentions_as(&mut *tx, actor, &state).await?;
                value["mentions_count"] = json!(value["mentions"].as_array().map_or(0, Vec::len));
            }
        }
        if value["type"] == "Document" && value["kind"] == "attachment" {
            value["blob"] = serde_json::to_value(
                kernel::blobs::metadata_optional(&mut *tx, actor, &record.id).await?,
            )?;
        }
        let links_started = std::time::Instant::now();
        let links = links
            .iter()
            .filter(|link| link["source_id"] == id || link["target_id"] == id)
            .cloned()
            .collect::<Vec<_>>();
        tracing::debug!(target:"native_ce::read_staging",phase="record_links",elapsed_us=links_started.elapsed().as_micros() as u64);
        for (field, endpoint) in [("links_out", "source_id"), ("links_in", "target_id")] {
            let direction: Vec<_> = links.iter().filter(|link| link[endpoint] == id).collect();
            value[format!("{field}_count")] = json!(direction.len());
            value[field] = json!(direction
                .into_iter()
                .skip(links_offset)
                .take(links_limit)
                .collect::<Vec<_>>());
        }
        // Direct thread children ride every row: the count always, the
        // anchored summaries only with include_comments. A hidden record
        // stays not_found above, so its comments never leak.
        let comments_started = std::time::Instant::now();
        let enriched = comments::enrich_on(
            conn,
            actor,
            &record,
            include_comments,
            comments_limit,
            comments_offset,
        )
        .await?;
        tracing::debug!(target:"native_ce::read_staging",phase="get_comments",elapsed_us=comments_started.elapsed().as_micros() as u64);
        value["comment_count"] = enriched["comment_count"].clone();
        if let Some(comments) = enriched.get("comments") {
            value["comments"] = comments.clone();
        }
        // Definition-driven disclosures ride the admitted link batch, never
        // the caller-sized links window: links_limit cannot suppress them.
        let disclosed =
            read_disclosures::disclosures_for(conn, actor, &[(id, links.as_slice())]).await?;
        if let Some(rules) = disclosed.get(id) {
            value["read_disclosures"] = json!(rules);
        }
        Ok(Some(value))
    } else {
        Ok(None)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryArgs {
    steps: Vec<Value>,
    projection: Option<crate::mcp::tools::querying::RecordProjection>,
    limit: Option<usize>,
    offset: Option<usize>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Filter {
    step: String,
    types: Option<Vec<String>>,
    kinds: Option<Vec<String>>,
    ids: Option<Vec<String>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Traverse {
    step: String,
    target: String,
    relationship: String,
    direction: Option<String>,
}

async fn query_record(db: &Db, actor: &str, args: Value) -> Result<Value> {
    kernel::read_cache::with_capabilities(query_record_read(db, actor, args)).await
}
async fn query_record_read(db: &Db, actor: &str, args: Value) -> Result<Value> {
    if crate::mcp::tools::record_hook::requested(&args) {
        let (sql, parameters, limit, offset) =
            crate::mcp::tools::record_hook::kernel_statement(&args)?;
        let answer =
            sql::query_sql(db, actor, json!({"sql": sql, "parameters": parameters})).await?;
        let rows = answer
            .get("rows")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| {
                crate::Error::engine("query_record: record_hook.v1 SQL result omitted rows")
            })?;
        let mut connection = db.pool().acquire().await?;
        let interpreter = kernel::v1_state::interpreter_on(&mut connection, actor).await?;
        return crate::mcp::tools::record_hook::project_page(&interpreter, rows, limit, offset);
    }
    let extended = args.get("order").is_some()
        || args["steps"].as_array().is_some_and(|steps| {
            steps.len() == 2
                || steps.iter().any(|step| {
                    step.as_object().is_some_and(|fields| {
                        fields.keys().any(|key| {
                            ![
                                "step",
                                "types",
                                "kinds",
                                "ids",
                                "target",
                                "relationship",
                                "direction",
                            ]
                            .contains(&key.as_str())
                        })
                    }) || (step["step"] == "traverse" && step.get("relationship").is_none())
                })
        });
    if extended {
        return sql::with_query_record_guard_diagnostics(read_surface::query_record(
            db, actor, args,
        ))
        .await;
    }
    let args: QueryArgs = parse("query_record", args)?;
    let metadata_only = args.projection.is_some();
    let limit = args.limit.unwrap_or(50);
    let offset = args.offset.unwrap_or(0);
    if !(1..=500).contains(&limit) {
        return Err(Error::engine(
            "query_record: limit must be between 1 and 500",
        ));
    }
    // Exactly one filter, or one exact starting id -> directed link -> filter.
    // The final filter uses ordinary primary types, never definition families.
    let (filter, linked) = match args.steps.as_slice() {
        [filter] => (filter, None),
        [start, traverse, filter] => {
            let start: Filter = parse("query_record", start.clone())?;
            let traverse: Traverse = parse("query_record", traverse.clone())?;
            let Some(ids) = start.ids else {
                return Err(unsupported(
                    "query_record",
                    "link start without one exact id",
                ));
            };
            if start.step != "filter"
                || ids.len() != 1
                || start.types.is_some()
                || start.kinds.is_some()
                || traverse.step != "traverse"
                || traverse.target != "links"
            {
                return Err(unsupported(
                    "query_record",
                    "pipeline; expected one exact id -> links -> filter",
                ));
            }
            // query_as measures direction from the candidate to the anchor.
            let direction = match traverse.direction.as_deref() {
                None | Some("both") => "either",
                Some("out") => "in",
                Some("in") => "out",
                _ => return Err(unsupported("query_record", "link direction")),
            };
            (
                filter,
                Some((traverse.relationship, ids[0].clone(), direction)),
            )
        }
        _ => {
            return Err(unsupported(
                "query_record",
                "pipeline; use one filter or exact id -> links -> filter",
            ))
        }
    };
    let filter: Filter = parse("query_record", filter.clone())?;
    if filter.step != "filter" {
        return Err(unsupported("query_record", "step other than filter"));
    }
    // Bounded S7a path: groups from one DISTINCT query, indexed group scans
    // with cached visibility, hydration strictly for the returned window —
    // no full-record loads, no per-record MAX(seq) loop, no bodies.
    let groups = kernel::search_v2::distinct_groups(db).await?;
    let linked_to = linked
        .as_ref()
        .map(|(rel, id, direction)| (rel.as_str(), id.as_str(), *direction));
    let counters = kernel::search_v2::S7aCounters::default();
    let page = kernel::search_v2::bounded_query_as(
        db,
        actor,
        &groups,
        filter.ids.as_deref(),
        filter.types.as_deref(),
        filter.kinds.as_deref(),
        linked_to,
        limit,
        offset,
        &counters,
    )
    .await?;
    let placement_started = std::time::Instant::now();
    let mut snapshot = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut snapshot, actor).await?;
    let identity = kernel::read_cache::key_on(&mut snapshot, actor, "query_placement").await?;
    let mut records = kernel::read_cache::in_pinned_snapshot(
        identity,
        kernel::read_cache::connection_id(&mut snapshot),
        async { bounded_page_on(&mut snapshot, actor, &page, metadata_only).await },
    )
    .await?;
    snapshot.rollback().await?;
    tracing::debug!(target:"native_ce::read_staging",phase="query_placement",elapsed_us=placement_started.elapsed().as_micros() as u64);
    // The built-in workbench hydrates inbox routing and author exclusion from
    // this bounded list. These are governed Message metadata, not body reads.
    // Finish placement first so the read snapshot never holds a pool slot
    // while asking placement to acquire another one.
    if !metadata_only
        && page
            .records
            .iter()
            .any(|r| r.primary_type.as_deref() == Some("Message"))
    {
        let mut tx = db.pool().begin().await?;
        kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
        for (record, value) in page.records.iter().zip(records.iter_mut()) {
            if record.primary_type.as_deref() != Some("Message") {
                continue;
            }
            kernel::kernel_require(
                &mut tx,
                actor,
                &record.id,
                crate::authorization::Capability::View,
            )
            .await?;
            value["owner_id"] =
                json!(messaging::visible_person(&mut tx, actor, record.owner_id.as_deref()).await?);
            if let Some(state) = kernel::messaging::on(&mut tx, &record.id).await? {
                value["communication_origin"] =
                    kernel::messaging::communication_origin(&mut tx, &state).await?;
                if let Some(created) = state.created_at {
                    value["created_at"] = json!(created);
                }
            }
        }
        tx.rollback().await?;
    }
    let returned = records.len();
    let mut payload = json!({"shape": "records", "records": records, "total": page.total,
        "returned": returned, "offset": offset, "has_more": offset.saturating_add(returned) < page.total});
    if metadata_only {
        crate::mcp::tools::querying::project_record_metadata(&mut payload);
    }
    Ok(payload)
}

/// v1-shaped JSON for one bounded-query hit. Same envelope keys as
/// `record_value` (which stays the get_record path); the body lane is absent
/// by construction — lists never read it.
async fn bounded_page_on(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    page: &kernel::search_v2::BoundedQueryPage,
    metadata_only: bool,
) -> Result<Vec<Value>> {
    let mut records = Vec::with_capacity(page.records.len());
    for record in &page.records {
        let home = crate::v1_import::placement_on(&mut *conn, actor, &record.id)
            .await?
            // Do not attach a newer placement to an older bounded-list hit.
            .filter(|p| p.kernel_home_id == record.home_id)
            .and_then(|p| p.home_id);
        if record.primary_type.as_deref() == Some("Message") {
            let message = if metadata_only {
                kernel::read_record_metadata_on(&mut *conn, actor, &record.id).await?
            } else {
                kernel::read_record_on(&mut *conn, actor, &record.id).await?
            };
            if let Some(message) = message {
                records.push(
                    record_value_projection_on(
                        &mut *conn,
                        actor,
                        &message,
                        if metadata_only {
                            ValueProjection::Metadata
                        } else {
                            ValueProjection::Full
                        },
                    )
                    .await?,
                );
            }
        } else {
            records.push(bounded_value_projection(record, home, metadata_only));
        }
    }
    // Same admitted-batch disclosures as Get, computed once per page
    // on this snapshot rather than per row.
    let ids: Vec<String> = page
        .records
        .iter()
        .map(|record| record.id.clone())
        .collect();
    let anchor_set: std::collections::BTreeSet<String> = ids.iter().cloned().collect();
    let batch = kernel::generic_links::visible_link_rows_for_on(&mut *conn, actor, &ids).await?;
    let by_anchor = read_disclosures::partition_links(batch, &anchor_set);
    let refs: Vec<(&str, &[Value])> = ids
        .iter()
        .map(|id| {
            (
                id.as_str(),
                by_anchor.get(id).map(Vec::as_slice).unwrap_or(&[]),
            )
        })
        .collect();
    let disclosed = read_disclosures::disclosures_for(&mut *conn, actor, &refs).await?;
    for (record, value) in page.records.iter().zip(records.iter_mut()) {
        if let Some(rules) = disclosed.get(&record.id) {
            value["read_disclosures"] = json!(rules);
        }
    }
    Ok::<_, Error>(records)
}

fn bounded_value_projection(
    record: &kernel::search_v2::BoundedRecord,
    home: Option<String>,
    metadata_only: bool,
) -> Value {
    let field = |name: &str| record.fields.get(name).cloned().unwrap_or(Value::Null);
    if metadata_only {
        return json!({
            "id":record.id,"type":record.primary_type,"kind":record.kind,
            "name":record.fields.get("title").cloned().unwrap_or_else(|| field("name")),
            "summary":field("summary"),"home_id":home,"maturity":record.metadata.maturity,
            "updated_at":null,"last_activity_at":record.metadata.last_activity_at
        });
    }
    json!({
        "id": record.id, "type": record.primary_type, "kind": record.kind,
        "name": record.fields.get("title").cloned().unwrap_or_else(|| field("name")), "body": field("body"), "summary": field("summary"),
        "home_id": home, "owner_id": record.owner_id,
        "persistence": record.metadata.persistence, "maturity": record.metadata.maturity,
        "created_at": record.created_at, "updated_at": null, "last_activity_at": record.metadata.last_activity_at,
        "deleted_at": null,
        "fields": record.fields, "record_version": format!("rec:{}", record.revision),
        "kernel_v2": {"family": record.family, "pin": record.pin, "interpreter": record.interpreter}
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchArgs {
    query: String,
    scope: Option<String>,
    limit: Option<i64>,
    include_archived: Option<bool>,
}

/// Tiered full-text search over the v2 kernel: v1 argument and response
/// shapes and kernel visibility. Optional filing scope intersects candidates;
/// pass a filter to `query_record` to narrow.
async fn search(db: &Db, actor: &str, args: Value) -> Result<Value> {
    kernel::read_cache::with_capabilities(search_read(db, actor, args)).await
}
async fn search_read(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let args: SearchArgs = parse("search", args)?;
    if args.query.trim().is_empty() {
        return Err(Error::engine(
            "search (kernel-v2): 'query' must be non-empty",
        ));
    }
    let scope_ids = match args.scope.as_deref() {
        Some(id) => Some(read_surface::scope_ids(db, actor, id).await?),
        None => None,
    };
    let limit = args.limit.unwrap_or(20);
    if limit <= 0 {
        return Err(Error::engine("search (kernel-v2): limit must be positive"));
    }
    let limit = limit.min(200);
    let core_started = std::time::Instant::now();
    let (hits, truncated) = match scope_ids.as_deref() {
        Some(ids) => {
            kernel::search_v2::search_scoped_as(
                db,
                actor,
                &args.query,
                limit,
                args.include_archived.unwrap_or(false),
                Some(ids),
            )
            .await?
        }
        None => {
            kernel::search_v2::search_as(
                db,
                actor,
                &args.query,
                limit,
                args.include_archived.unwrap_or(false),
            )
            .await?
        }
    };
    tracing::debug!(target:"native_ce::read_staging",phase="search_core",elapsed_us=core_started.elapsed().as_micros() as u64);
    // Truncation (scan backstop) reads like a full page to the caller: the
    // guidance below says more may exist.
    let limit_reached = truncated || hits.len() as i64 == limit;
    let placement_started = std::time::Instant::now();
    let mut snapshot = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut snapshot, actor).await?;
    let identity = kernel::read_cache::key_on(&mut snapshot, actor, "search_placement").await?;
    let rendered = kernel::read_cache::in_pinned_snapshot(identity, kernel::read_cache::connection_id(&mut snapshot), async {
        let mut rendered_hits = Vec::with_capacity(hits.len());
        for hit in &hits {
            let home_id = crate::v1_import::placement_on(&mut snapshot, actor, &hit.id)
                .await?
                .filter(|p| p.kernel_home_id == hit.home_id)
                .and_then(|p| p.home_id);
            rendered_hits.push(json!({"id":hit.id,"type":hit.record_type,"kind":hit.kind,"name":hit.name,"home_id":home_id,"score":hit.score,"snippet":hit.snippet}));
        }
        // Disclosures ride the same admitted batch and snapshot as Get, and
        // are independent of any link paging: search has none to suppress.
        let ids: Vec<String> = hits.iter().map(|hit| hit.id.clone()).collect();
        let anchor_set: std::collections::BTreeSet<String> =
            ids.iter().cloned().collect();
        let batch =
            kernel::generic_links::visible_link_rows_for_on(&mut snapshot, actor, &ids).await?;
        let by_anchor = read_disclosures::partition_links(batch, &anchor_set);
        let refs: Vec<(&str, &[Value])> = ids
            .iter()
            .map(|id| {
                (
                    id.as_str(),
                    by_anchor.get(id).map(Vec::as_slice).unwrap_or(&[]),
                )
            })
            .collect();
        let disclosed = read_disclosures::disclosures_for(&mut snapshot, actor, &refs).await?;
        for (hit, out) in hits.iter().zip(rendered_hits.iter_mut()) {
            if let Some(rules) = disclosed.get(&hit.id) {
                out["read_disclosures"] = json!(rules);
            }
        }
        Ok::<_, Error>(rendered_hits)
    }).await;
    snapshot.rollback().await?;
    let rendered_hits = rendered?;
    tracing::debug!(target:"native_ce::read_staging",phase="search_placement",elapsed_us=placement_started.elapsed().as_micros() as u64);
    let mut payload = json!({
        "query": args.query, "scope": args.scope,
        "hits": rendered_hits,
        "total": hits.len(), "returned": hits.len(),
        "limit": limit, "limit_reached": limit_reached, "thin": false,
    });
    if limit_reached {
        payload["guidance"] = json!(
            "This list may be incomplete. Use query_record with a filter step for a narrow, exhaustive answer."
        );
    }
    Ok(payload)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryArgs {
    record_id: String,
    #[serde(alias = "after_seq")]
    after_local_seq: Option<i64>,
    limit: Option<usize>,
    order: Option<String>,
    detail: Option<String>,
    include_import_receipts: Option<bool>,
}
pub(crate) async fn get_history(db: &Db, actor: &str, args: Value) -> Result<Value> {
    kernel::read_cache::with_capabilities(get_history_read(db, actor, args)).await
}
async fn get_history_read(db: &Db, actor: &str, args: Value) -> Result<Value> {
    if args.get("record_id").is_none_or(Value::is_null)
        || args.get("for_run").is_some()
        || args.get("include_child_runs").is_some()
    {
        return read_surface::history(db, actor, args).await;
    }
    record_history(db, actor, args).await
}
async fn record_history(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let args: HistoryArgs = parse("get_history", args)?;
    let limit = args.limit.unwrap_or(100);
    if !(1..=1000).contains(&limit) {
        return Err(Error::engine(
            "get_history limit must be between 1 and 1000",
        ));
    }
    if args
        .detail
        .as_deref()
        .is_some_and(|d| !matches!(d, "metadata" | "full"))
    {
        return Err(unsupported("get_history", "detail"));
    }
    let order = args.order.as_deref().unwrap_or("oldest_first");
    if !matches!(order, "oldest_first" | "newest_first") {
        return Err(unsupported("get_history", "order"));
    }
    // history_as covers records, homes and principals with the same absence
    // for hidden/missing subjects. Empty streams are a refusal in v1.
    let full = args.detail.as_deref() == Some("full");
    let include_import = args.include_import_receipts.unwrap_or(false);
    let mut events = Vec::new();
    let mut after = args.after_local_seq;
    let mut observed = false;
    loop {
        let page = kernel::history_page_as(
            db,
            actor,
            &args.record_id,
            after,
            order == "newest_first",
            (limit + 1).min(256),
            full,
            include_import,
        )
        .await?;
        if page.is_empty() {
            break;
        }
        observed = true;
        let next = page.last().unwrap().seq;
        if Some(next) == after {
            return Err(Error::engine("history cursor did not advance"));
        }
        after = Some(next);
        events.extend(
            page.into_iter()
                .filter(|event| include_import || !migration_event(event)),
        );
        if events.len() > limit {
            break;
        }
    }
    if !observed && args.after_local_seq.is_none() {
        return Err(Error::engine(format!(
            "get_history: record {} does not exist",
            args.record_id
        )));
    }
    let has_more = events.len() > limit;
    let selected = events.into_iter().take(limit).collect::<Vec<_>>();
    let next = has_more.then(|| selected.last().unwrap().seq);
    let mut events = history_values(selected, full, Some(&args.record_id));
    let mut source_snapshot = db.pool().begin().await?;
    if kernel::read_record_on(&mut source_snapshot, actor, &args.record_id)
        .await?
        .is_some()
    {
        if let Some((source, act, created)) =
            webhooks::recorded_source_on(&mut source_snapshot, &args.record_id, i64::MAX).await?
        {
            let ids: Vec<String> = sqlx::query_scalar(
                "SELECT id FROM main.content_events WHERE record_id=? AND act=?",
            )
            .bind(&args.record_id)
            .bind(act)
            .fetch_all(&mut *source_snapshot)
            .await?;
            for event in &mut events {
                if event["id"]
                    .as_str()
                    .is_some_and(|id| ids.iter().any(|known| known == id))
                {
                    event["source"] = source.clone();
                    event["contribution"] = webhooks::contribution(
                        &source,
                        &created,
                        event["id"].as_str().unwrap_or(""),
                        event["type"].as_str().unwrap_or(""),
                    );
                    event["delegation_principal"] = event["actor"].clone();
                    event["actor"] = Value::Null;
                    event["actor_name"] = "Delegated service".into();
                }
            }
        }
    }
    source_snapshot.rollback().await?;
    let native_versions = events
        .iter()
        .any(|event| event.get("native_event_type").is_some());
    let retained = events
        .iter()
        .any(|event| event["legacy_interpretation"] == true);
    Ok(
        json!({"local_database_id": null, "events": events, "next_after_local_seq": next,
        "legacy_provenance": crate::v1_import::legacy_record_provenance_as(db, actor, &args.record_id).await?,
        "order": order, "representation": {"detail": if full {"full"} else {"metadata"},
        "payloads": if native_versions {"native_body_versions_and_retained_v1_when_disclosed"} else if !retained {"unavailable"} else if full {"retained_v1"} else {"omitted"},
        "legacy_payloads": "retained v1 interpretation; payloads and event visibility redacted for the caller"}}),
    )
}

fn history_values(
    selected: Vec<kernel::KernelHistoryEvent>,
    full: bool,
    legacy_subject: Option<&str>,
) -> Vec<Value> {
    let mut events = Vec::new();
    for e in selected {
        let id = &e.id;
        let actor_name = &e.actor_name;
        let mut value = json!({
            "local_seq": e.seq, "id": id, "record_id": e.record_id, "type": logical_event_type(&e.event_type),
            "actor": e.actor, "actor_name": actor_name, "created_at": e.created_at,
            "run_key": e.run_key, "parent_key": null, "intent": null, "causal_envelope": null,
            "payload_omitted": true, "payload_json_utf8_bytes": null, "changed_fields": null
        });
        if let Some(native) = e.native_body_version {
            let mut payload = native["coedit"].as_object().cloned().unwrap_or_default();
            payload.insert("body".into(), native["body"].clone());
            value["payload"] = Value::Object(payload);
            value["native_event_type"] = json!(e.event_type);
            value = super::tools::history::shape_history_event(
                value,
                super::tools::history::HistoryDetail::Full,
            );
            value["payload_omitted"] = json!(false);
        }
        if let Some(legacy) = e.retained_legacy {
            value["type"] = legacy["event_type"].clone();
            value["record_id"] = json!(legacy_subject.unwrap_or(&e.record_id));
            value["causal_status"] = json!("legacy_unknown");
            value["legacy_interpretation"] = json!(true);
            value["run_key"] = json!(e.run_key);
            if legacy.get("payload").is_some() {
                value["payload"] = legacy["payload"].clone();
                value = super::tools::history::shape_history_event(
                    value,
                    if full {
                        super::tools::history::HistoryDetail::Full
                    } else {
                        super::tools::history::HistoryDetail::Metadata
                    },
                );
                if full {
                    value["payload_omitted"] = json!(false);
                }
            }
        }
        events.push(value);
    }
    events
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod describe_schema_tests;

#[cfg(test)]
mod guidance_tests;

#[cfg(test)]
mod policy_tests;

pub(crate) use coordination::{bootstrap_principal_on, selected_standing_instructions_on};

pub(crate) use messaging::visible_person as member_visible_person_on;
pub(crate) use read_surface::{
    artifact_kind_tokens as native_artifact_kind_tokens,
    containment_path_visible_on as native_containment_path_visible_on, custody_boundary_on,
    query_hidden_predicate as native_query_hidden_predicate, root_on as member_virtual_root_on,
    ATTRIBUTION_KIND as NATIVE_ATTRIBUTION_KIND,
    QUERY_OPT_IN_FAMILIES as NATIVE_QUERY_OPT_IN_FAMILIES,
};
pub(crate) use writes::short_reference as member_display_reference_on;

/// Qualified hosted entry point; callers supply retained exact pins, never a
/// mutable active-name lookup. Other serving profiles have no equivalent route.
pub(crate) async fn query_pinned_saved_sql(
    db: &Db,
    actor: &str,
    definition: &crate::named_views::contract::SavedSqlV12,
) -> Result<Value> {
    definition.validate_current()?;
    let order = definition
        .output
        .order
        .iter()
        .map(|o| {
            format!(
                "\"{}\" {}",
                o.column,
                match o.direction {
                    crate::mcp::tools::querying::SavedSqlDirection::Asc => "ASC",
                    crate::mcp::tools::querying::SavedSqlDirection::Desc => "DESC",
                }
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT * FROM ({}) AS saved_governed_projection ORDER BY {order} LIMIT {}",
        definition.sql.trim().trim_end_matches(';'),
        definition.bounds.rows.saturating_add(1)
    );
    sql::query_stored_saved_sql(
        db,
        actor,
        json!({"sql":sql,"parameters":definition.parameters,"_named_view_pins":definition.roots()}),
    )
    .await
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
mod current_body_read_tests;

#[cfg(all(test, feature = "v2-kernel-probe"))]
mod merge_body_tests;

#[cfg(test)]
mod schema_config_operations_tests;

#[cfg(all(test, feature = "v2-kernel-probe"))]
mod url_attachment_tests;

/// Enable the cross-request visible-set cache for a read-write **serving**
/// handle (Native b171a9d / 788c170). Lazily creates the persisted access
/// epoch in a writer transaction and registers the handle's cache. Call only
/// from hosted serving when it opens a workspace's read-write serving handle;
/// never from generic, inspection, CLI, standby or member opens. A no-op for
/// any other open mode.
pub async fn start_serving_visible_cache(db: &crate::Db) -> crate::Result<()> {
    sql::visible_cache::start_serving(db).await
}

/// Unregister a retired serving handle's visible-set cache.
pub fn stop_serving_visible_cache(db: &crate::Db) {
    sql::visible_cache::stop_serving(db);
}

/// Settlement's closed variant-8/create-9 capture profile always includes the
/// original mint proof. It never derives historical identity from live flags.
#[cfg(test)]
pub(crate) fn register_original_settlement_contract_profile(
    registry: &mut ToolRegistry,
) -> Result<()> {
    contracts::register_minted_id_contracts(registry, &["create_record"])
}
