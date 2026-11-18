//! The installed v2 physical catalogue, in v1's `describe_schema` shape.
//!
//! v2 has no logical v1 tables: `sql_read` serves caller-visible logical
//! relations computed from kernel projections. This tool describes the
//! physical tier — what the file actually holds and which tier each table
//! belongs to — for engine and storage work. It grants no `query_sql`
//! authority over anything it lists, and it exposes no record. Members see an
//! explicit allowlist of classified tables (below); the rest is the database
//! owner's repair information.
use super::*;
use sha2::{Digest, Sha256};
use sqlx::Row;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    include_ddl: Option<bool>,
}

/// Physical tables a non-owner may see described.
///
/// The catalogue is read from the live `sqlite_schema`, so this is an
/// allowlist, not a deny list: a table added later stays invisible to members
/// until someone classifies it here. Hiding a table never hides a member's
/// own data — every member-facing read goes through a logical relation or an
/// operation, and those are unaffected.
///
/// The set mirrors v1's owner gate: content, definition and run tiers are
/// described to members; policy, identity and instruction bindings, account
/// config, disclosure bookkeeping, import/legacy substrate, write receipts,
/// provider-observation state, the byte tier and derived search indexes are
/// the owner's repair information.
const MEMBER_VISIBLE_TABLES: &[&str] = &[
    // Event log and its structural companions.
    "act_cutover",
    "act_state",
    "content_event_causal_cutover",
    "content_event_causal_frontier",
    "content_event_heads",
    "content_events",
    // Definition, package and rule registry.
    "consumer_requirements",
    "definition_adoptions",
    "definition_artifacts",
    "kernel_adoptions",
    "kernel_package_selections",
    "package_artifacts",
    "rule_installations",
    // Record, link and facet projections.
    "kernel_artifact_closures",
    "kernel_comment_anchors",
    "kernel_facet_time_invalid",
    "kernel_facet_time_meta",
    "kernel_facet_time_rows",
    "kernel_facets",
    "kernel_generic_links",
    "kernel_lifecycle",
    "kernel_link4_edges",
    "kernel_links",
    "kernel_provider_link_heads",
    "kernel_provider_link_rows",
    "kernel_record_bodies",
    "kernel_record_fields",
    "kernel_record_metadata",
    "kernel_records",
    "kernel_roots",
    // Canvas, apps, saved tabs, publications.
    "canvas_batches",
    "canvas_objects",
    "kernel_app_actions",
    "kernel_app_consent_revocations",
    "kernel_app_install_outcomes",
    "kernel_app_installs",
    "kernel_app_package_sources",
    "kernel_app_state",
    "kernel_canvas_activations",
    "kernel_canvas_source_events",
    "kernel_publications",
    "kernel_saved_tabs",
    // Messaging and runs.
    "kernel_message_destinations",
    "kernel_message_interactions",
    "kernel_message_people",
    "kernel_message_receipts",
    "kernel_messages",
    "kernel_notification_preferences",
    "kernel_personas",
    "kernel_runs",
    "kernel_slot_lineage",
    "kernel_slots",
];

fn member_visible(table: &str) -> bool {
    MEMBER_VISIBLE_TABLES.contains(&table)
}

/// The authority tier of one physical table.
///
/// Kernel replay rebuilds every table `kernel::projection_dump` does not
/// exclude — that coverage is schema-derived, so a table added later is
/// classified honestly rather than silently called authoritative.
fn table_role(table: &str) -> &'static str {
    match table {
        "content_events" => "authoritative (append-only content event log)",
        "meta_events" => "authoritative (append-only definition and meta event log)",
        "act_state" | "act_cutover" => "authoritative companion (act log state and cutover)",
        "content_event_causal_frontier" | "content_event_causal_cutover" => {
            "authoritative companion (event-log causal closure)"
        }
        "content_event_heads" => {
            "trigger-maintained function of content_events (not a replayable projection)"
        }
        "kernel_blobs" => "substrate (byte tier, direct-write by design)",
        "kernel_legacy_sql_progress" => {
            "derived recovery progress (import scan cursor, not user content)"
        }
        table if table.starts_with("kernel_standby_") => {
            "local standby bookkeeping (never hosted state)"
        }
        table if table.starts_with("kernel_search_fts") => {
            "derived index (kernel full-text search; rebuilt by replay)"
        }
        _ if kernel::projection_dump::EXCLUDED_TABLES.contains(&table) => {
            "substrate (v2 kernel-owned; not rebuilt by kernel replay)"
        }
        // A v1 store table retained verbatim in a prepared v2 file keeps v1's
        // own tier label instead of being described as a kernel projection.
        _ if crate::schema::REQUIRED_TABLES.contains(&table) => {
            crate::schema::discovery::table_role(table)
        }
        _ => "projection (rebuildable by kernel replay; never write directly)",
    }
}

const LOGICAL_RELATIONS: &str = "sql_read serves v2's caller-visible logical relations over \
     these projections, not the physical tables below. Start from the relation card in the \
     sql_read descriptor, or query SELECT relation_name, column_name, column_position FROM \
     catalog_columns ORDER BY relation_name, column_position (notes in catalog_relations).";

const MODEL: &str = "event-authoritative: content_events is authoritative for every content \
     projection (records and their fields, facets, links, messages, comments, publications, \
     canvas, saved tabs, app installs, runs and portable policy); meta_events is authoritative \
     for definition artifacts and their adoptions. Everything else here is a kernel or \
     definition projection rebuilt by kernel replay, or named substrate, and must never be \
     written directly. The v1 tables records, links, facet_values, facet_observations and \
     policy_entries are absent by design: v2 serves them as logical relations computed from \
     these projections. This catalogue describes storage, not authority: it grants no query_sql \
     access, and per-caller visibility stays enforced on every logical relation.";

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_engine_handler(
        "describe_schema",
        EngineKind::KernelV2,
        |engine, caller, arguments| async move {
            let EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            // Admission, not authorization: a v2 surface serves only a bound,
            // admitted principal. The catalogue itself is not caller-relative
            // beyond the member/owner tier below.
            let actor = principal(&db, &caller).await?;
            describe(&db, &actor, &caller, arguments).await
        },
    )
}

async fn describe(db: &Db, actor: &str, caller: &Caller, arguments: Value) -> Result<Value> {
    let args: Args = parse("describe_schema", arguments)?;
    let include_ddl = args.include_ddl.unwrap_or(false);
    // v1, Turso-local and Postgres all reserve physical DDL for the database
    // owner; v2 keeps that boundary rather than inventing a different one.
    if include_ddl && !caller.is_host_owner() {
        return Err(Error::auth(
            "describe_schema: database owner host role required for physical DDL",
        ));
    }
    let owner = caller.is_host_owner();
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    let catalog = sqlx::query(
        "SELECT name,sql FROM main.sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*' ORDER BY name",
    )
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .map(|row| -> Result<(String, Option<String>)> {
        Ok((row.try_get("name")?, row.try_get("sql")?))
    })
    .collect::<Result<Vec<_>>>()?;
    // The digest covers the whole installed catalogue, so it identifies the
    // database rather than the caller's filtered view of it.
    let mut hasher = Sha256::new();
    for (table, ddl) in &catalog {
        hasher.update(table.as_bytes());
        hasher.update(b"\n");
        hasher.update(ddl.as_deref().unwrap_or_default().as_bytes());
        hasher.update(b"\n");
    }
    let ddl_fingerprint = hex::encode(hasher.finalize());

    let mut tables = Vec::new();
    let mut statements = Vec::new();
    for (table, ddl) in catalog {
        if !owner && !member_visible(&table) {
            continue;
        }
        // `table_info` hides generated columns; `table_xinfo` returns ordinary
        // columns with the same fields and also exposes virtual ones.
        let columns = sqlx::query(
            r#"SELECT name,type,"notnull",pk FROM pragma_table_xinfo(?1,'main') ORDER BY cid"#,
        )
        .bind(&table)
        .fetch_all(&mut *tx)
        .await?
        .iter()
        .map(|row| -> Result<Value> {
            Ok(crate::schema::discovery::column(
                &table,
                row.try_get::<String, _>("name")?,
                row.try_get::<String, _>("type")?,
                row.try_get::<i64, _>("notnull")? != 0,
                row.try_get::<i64, _>("pk")? != 0,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
        tables.push(json!({
            "name": table,
            "role": table_role(&table),
            "columns": columns,
        }));
        if include_ddl {
            if let Some(ddl) = ddl {
                statements.push(ddl);
            }
        }
    }
    let user_version: i64 = sqlx::query_scalar("PRAGMA main.user_version")
        .fetch_one(&mut *tx)
        .await?;
    tx.rollback().await?;

    let mut out = json!({
        "logical_relations": LOGICAL_RELATIONS,
        "engine": {
            "name": "native-kernel-v2",
            "version": crate::ENGINE_VERSION,
            "git_sha": crate::GIT_SHA,
            // v2 has no versioned v1 SQLite schema; its empty user_version and
            // the installed-DDL digest are the honest identity of this file.
            "schema_version": 0,
            "supported_schema_baseline": 0,
            "user_version": user_version,
            "ddl_fingerprint": ddl_fingerprint,
        },
        "model": MODEL,
        "tables": tables,
    });
    if include_ddl {
        out["ddl_statements"] = json!(statements);
    }
    Ok(out)
}
