//! Probe-gated coordination over kernel-owned run and claim authority.
use super::*;
use crate::v2_standard::claims_v1::Command;

const OMISSIONS: &[&str] = &[
    "Onboarding programmes and member state are imported read-only; obligation delivery and mutation are unavailable.",
    "Purpose-relative briefing, resumability, overlap, comments and dependency context are not implemented.",
    "Standing instructions resolve imported workspace and member bindings; template provenance is unavailable.",
    "Run model/client declarations, interaction capture and realtime wakeups are not implemented.",
];

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    macro_rules! handler {
        ($name:literal, $handler:ident) => {
            registry.register_engine_handler(
                $name,
                EngineKind::KernelV2,
                |engine, caller, args| async move {
                    let EngineHandle::KernelV2(db) = engine else {
                        unreachable!()
                    };
                    let actor = principal(&db, &caller).await?;
                    $handler(&db, &actor, &caller, args).await
                },
            )?;
        };
    }
    handler!("bootstrap", bootstrap);
    handler!("set_intent", set_intent);
    handler!("close_run", close_run);
    handler!("start_work", start_work);
    registry.extend_kernel_v2_arguments("start_work", json!({
        "operation_key": {"type":"string","description":"KernelV2: stable key for idempotent claim/release receipt retries."},
        "expected_generation": {"type":"integer","minimum":0,"description":"KernelV2: release generation from the claim response."},
        "expected_head": {"type":"integer","description":"KernelV2: release head from the claim response."}
    }))?;
    Ok(())
}

/// Look up a key without creating a run during observational reads.
pub(crate) async fn existing_run(
    db: &Db,
    actor: &str,
    key: &str,
) -> Result<Option<kernel::RunContext>> {
    let id: Option<String> = sqlx::query_scalar("SELECT r.id FROM kernel_runs r JOIN kernel_principals p ON p.principal_id=r.run_principal WHERE p.auth_binding=?")
        .bind(format!("mcp-run:{key}")).fetch_optional(db.write_pool()).await?;
    match id {
        Some(id) => Ok(Some(kernel::run_ledger::context_as(db, actor, &id).await?)),
        None => Ok(None),
    }
}

async fn run(db: &Db, actor: &str, caller: &Caller) -> Result<kernel::RunContext> {
    let key = caller.run_key().ok_or_else(|| {
        Error::engine(
            "kernel-v2 coordination requires a full run_key from bootstrap or run_key='new'",
        )
    })?;
    kernel::open_run_as(db, actor, key).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyArgs {}
async fn bootstrap(db: &Db, actor: &str, caller: &Caller, args: Value) -> Result<Value> {
    let _: EmptyArgs = parse("bootstrap", args)?;
    let read_only = caller.request_persistence_suppressed();
    let (key, context) = if read_only {
        let key = caller.run_key().map(str::to_owned);
        let context = match key.as_deref() {
            Some(key) => existing_run(db, actor, key).await?,
            None => None,
        };
        (key, context)
    } else {
        let (key, context) = match caller.run_key() {
            Some(key) => (key.to_owned(), kernel::open_run_as(db, actor, key).await?),
            None => kernel::run_ledger::mint_run_with_context_as(db, actor, None).await?,
        };
        (Some(key), Some(context))
    };
    let (kind, label): (String, String) =
        sqlx::query_as("SELECT kind,display_label FROM kernel_principals WHERE principal_id=?")
            .bind(actor)
            .fetch_one(db.write_pool())
            .await?;
    let workspace_name = kernel::workspace_metadata::read(db)
        .await?
        .map(|metadata| metadata.name)
        .unwrap_or_else(|| "Native workspace".into());
    let instructions = standing_instructions(db, actor, caller).await?;
    let closed = match context.as_ref() {
        Some(context) => Some(kernel::run_witness_as(db, context).await?.closed),
        None => None,
    };
    let status = match closed {
        Some(true) => "closed",
        Some(false) => "open",
        None => "not_established",
    };
    let guidance = if read_only {
        "Read-only bootstrap: no run was created or updated. A carried key is correlation only unless an existing owned run was resolved."
    } else if closed == Some(true) {
        "This run is closed. Its key is retained for correlation; writes requiring an open run will fail run_closed. Bootstrap without this key (or with run_key='new') to start a new run."
    } else {
        "Reuse this exact run_key on subsequent calls, reads included. Declare intent separately with set_intent; close with close_run."
    };
    Ok(json!({
        "principal": {"principal_id":actor, "kind":kind, "display_name":label, "identity_basis":"authenticated kernel auth_binding"},
        "workspace": {"primary_workspace":{"id":crate::events::KERNEL_ROOT_ID,"name":workspace_name}},
        "orientation":{"template_key":crate::instructions::ENGINE_ORIENTATION_TEMPLATE_KEY,
            "template_version":crate::instructions::ENGINE_ORIENTATION_TEMPLATE_VERSION,
            "content":crate::instructions::ENGINE_ORIENTATION},
        "instructions":instructions,
        "pending_obligations":kernel::v1_state::onboarding_as(db,actor,caller.is_host_member()).await?,
        "run":{"run_key":key,"closed":closed,"status":status,"read_only":read_only,"durable":context.is_some()},
        "session":{"run_key":key,"reuse_required":!read_only && closed == Some(false),"guidance":guidance},
        "unsupported_capabilities":OMISSIONS,
        "engine":{"name":"kernel-v2","probe_gated":true}
    }))
}

async fn standing_instructions(db: &Db, actor: &str, caller: &Caller) -> Result<Value> {
    // The import host preserves original v1 scope IDs and explicitly maps
    // account scopes to kernel principals. Membership is host-authenticated;
    // each target additionally passes ordinary kernel record visibility.
    let bindings: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT id,scope_kind,source_record_id FROM kernel_instruction_bindings
         WHERE enabled=1 AND ((scope_kind='database' AND scope_id='native:database' AND ?)
           OR (scope_kind='account' AND account_principal=?))
         ORDER BY CASE WHEN scope_kind='database' THEN 0 ELSE 1 END,position,source_record_id,id",
    )
    .bind(caller.is_host_member())
    .bind(actor)
    .fetch_all(db.write_pool())
    .await?;
    let mut entries = Vec::new();
    let mut diagnostics = Vec::new();
    let mut bytes = 0;
    for (binding, scope, id) in bindings {
        let record = kernel::read_record_as(db, actor, &id).await?;
        let Some(record) = record.filter(|r| !r.archived) else {
            // Workspace sources must be indistinguishable from absent bindings
            // when unreadable. Only the caller's own account layer may name
            // unavailable targets so they can repair their bindings.
            if scope == "database" {
                continue;
            }
            diagnostics.push(json!({"binding_id":binding,"record_id":id,"reason":"Bound instruction record is missing, archived or not visible to this caller."}));
            continue;
        };
        let title = record
            .fields
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("");
        let body = record.body.as_deref().unwrap_or("");
        if body.is_empty() {
            continue;
        }
        bytes += body.len();
        if bytes > crate::instructions::MAX_RESOLVED_INSTRUCTION_BYTES
            || entries.len() + diagnostics.len()
                >= crate::instructions::MAX_BOOTSTRAP_INSTRUCTION_ENTRIES
        {
            return Err(Error::engine("instruction_budget_exceeded: no partial standing instruction stack is authoritative"));
        }
        entries.push(json!({"entry_id":binding,"scope":if scope == "database" {"workspace"} else {"member"},
            "kind":"standing_instruction","source":{"type":"record","record_id":id,"title":title},"content":body}));
    }
    Ok(
        json!({"status":if diagnostics.is_empty() {"ready"} else {"partial"},
        "resolved_bytes":bytes,"limit_bytes":crate::instructions::MAX_RESOLVED_INSTRUCTION_BYTES,
        "entries":entries,"guidance":crate::instructions::NEUTRAL_PRECEDENCE_GUIDANCE,
        "diagnostics":diagnostics}),
    )
}

async fn set_intent(db: &Db, actor: &str, caller: &Caller, args: Value) -> Result<Value> {
    let mut acceptance = crate::mcp::tools::intent::declare_without_activity_briefing(args)?;
    let _context = run(db, actor, caller).await?;
    // The shared request lifecycle persists only after this handler accepts.
    acceptance["briefing"]["availability"]["reason"] = json!("kernel_v2_briefing_not_implemented");
    acceptance["declared_model"]["status"] = json!("unsupported");
    Ok(acceptance)
}
async fn close_run(db: &Db, actor: &str, caller: &Caller, args: Value) -> Result<Value> {
    let _: EmptyArgs = parse("close_run", args)?;
    let context = run(db, actor, caller).await?;
    let changed = kernel::finish_run_as(db, &context).await?;
    let started_at: String = sqlx::query_scalar(
        "SELECT created_at FROM content_events WHERE record_id=? AND type='kernel.run_opened.v1'",
    )
    .bind(context.run_id())
    .fetch_one(db.write_pool())
    .await?;
    let ended_at: String = sqlx::query_scalar(
        "SELECT created_at FROM content_events WHERE record_id=? AND type='kernel.run_closed.v1'",
    )
    .bind(context.run_id())
    .fetch_one(db.write_pool())
    .await?;
    Ok(
        json!({"activity_id":context.run_id(),"started_at":started_at,"ended_at":ended_at,"changed":changed,"closed":true}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkArgs {
    record_id: String,
    action: Option<String>,
    #[serde(rename = "agent_id")]
    _agent_id: Option<Value>,
    expected_holder_run_key: Option<String>,
    operation_key: Option<String>,
    expected_generation: Option<u64>,
    expected_head: Option<i64>,
}
async fn start_work(db: &Db, actor: &str, caller: &Caller, args: Value) -> Result<Value> {
    let args: WorkArgs = parse("start_work", args)?;
    let action = args.action.as_deref().unwrap_or("claim");
    if !["claim", "release", "preview"].contains(&action) {
        return Err(Error::engine("start_work: unknown action"));
    }
    let context = run(db, actor, caller).await?;
    let record = kernel::read_record_as(db, actor, &args.record_id)
        .await?
        .ok_or_else(|| Error::engine("hidden_or_missing"))?;
    let mut receipt = None;
    let mut changed = false;
    if action != "preview" {
        let retry_command = if action == "release" {
            if let Some(key) = args.operation_key.as_deref() {
                kernel::claims_port::release_retry_command_as(db, &context, &record.id, key).await?
            } else {
                None
            }
        } else {
            None
        };
        let command = if action == "claim" {
            Command::Claim
        } else if let Some(command) = retry_command {
            if let Command::Release {
                holder_run_id,
                generation,
                head,
            } = &command
            {
                if args.expected_generation.is_some_and(|g| g != *generation)
                    || args.expected_head.is_some_and(|h| h != *head)
                {
                    return Err(Error::conflict("claims retry key reused"));
                }
                if let Some(key) = args.expected_holder_run_key.as_deref() {
                    let expected = existing_run(db, actor, key)
                        .await?
                        .ok_or_else(|| Error::engine("unknown_run"))?;
                    if expected.run_id() != holder_run_id {
                        return Err(Error::conflict("claims retry key reused"));
                    }
                }
            }
            command
        } else {
            // Explicit generation and head fence release even across same-run ABA.
            // Ordinary v1 release callers get a snapshot of the current holder;
            // clients retrying a specific release should retain these witnesses.
            let holder = match args.expected_holder_run_key.as_deref() {
                Some(key) => existing_run(db, actor, key)
                    .await?
                    .ok_or_else(|| Error::engine("unknown_run"))?,
                None => context.clone(),
            };
            let state = kernel::claims_as(db, actor, std::slice::from_ref(&record.id))
                .await?
                .remove(0);
            Command::Release {
                holder_run_id: holder.run_id().into(),
                generation: args
                    .expected_generation
                    .or(state.generation)
                    .ok_or_else(|| Error::conflict("stale_claim"))?,
                head: args
                    .expected_head
                    .or(state.head)
                    .ok_or_else(|| Error::conflict("stale_claim"))?,
            }
        };
        let key = args
            .operation_key
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let request = kernel::prepare_claim_as(db, &context, &record.id, &key, command).await?;
        let (result, appended) =
            kernel::claims_port::commit_claim_with_change_as(db, &context, &request).await?;
        changed = appended;
        if let kernel::ClaimResult::Committed(committed) = result {
            receipt = Some(committed);
        }
    }
    let state = kernel::claims_as(db, actor, std::slice::from_ref(&record.id))
        .await?
        .remove(0);
    let held_key: Option<String> = if let Some(holder) = &state.holder {
        sqlx::query_scalar("SELECT substr(p.auth_binding,9) FROM kernel_runs r JOIN kernel_principals p ON p.principal_id=r.run_principal WHERE r.id=?")
            .bind(&holder.run_id).fetch_optional(db.write_pool()).await?
    } else {
        None
    };
    let work_state = if !state.occupied {
        json!({"state":"unclaimed"})
    } else if state.withheld {
        json!({"state":"claimed","details":{"visibility":"withheld"},"target":{"visibility":"withheld"}})
    } else {
        json!({"state":"claimed","details":{"visibility":"visible"},"target":{"visibility":"visible","account":actor,"run_key":held_key}})
    };
    Ok(
        json!({"record_id":record.id,"action":action,"changed":changed,"claimed":state.occupied,
        "lifecycle":record.fields.get("lifecycle"),"held_by":null,
        "held_by_account":state.holder.as_ref().map(|h| &h.principal),"held_by_run_key":held_key,
        "claimed_at":state.holder.as_ref().map(|h| &h.claimed_at),"work_state":work_state,
        "receipt":receipt,"generation":state.generation,"head":state.head,
        "context":{"status":"unavailable","reason":"Working context and overlap briefing are not implemented"},
        "retry_guidance":"Supply operation_key for receipt retries. For release, retain expected_holder_run_key, expected_generation and expected_head from the claim response."}),
    )
}

/// The v1 renderer assumes v1 destinations and a read-only bootstrap body.
/// Keep those claims out of the probe while retaining exact instruction text.
pub(crate) fn render_bootstrap_text(value: &Value) -> String {
    use std::fmt::Write as _;
    let text = |pointer| value.pointer(pointer).and_then(Value::as_str).unwrap_or("");
    let mut out = text("/orientation/content").to_owned();
    let _ = writeln!(
        out,
        "\n\n## Current footing\n\nPrincipal: {} (`{}`; {})\nWorkspace: {}\nWorkspace root: `{}`\n",
        text("/principal/display_name"),
        text("/principal/principal_id"),
        text("/principal/kind"),
        text("/workspace/primary_workspace/name"),
        text("/workspace/primary_workspace/id")
    );
    let _ = writeln!(
        out,
        "## Preserved standing instructions\n\n{}\n",
        crate::instructions::NEUTRAL_PRECEDENCE_GUIDANCE
    );
    if let Some(entries) = value
        .pointer("/instructions/entries")
        .and_then(Value::as_array)
    {
        for entry in entries {
            let field = |pointer| entry.pointer(pointer).and_then(Value::as_str).unwrap_or("");
            let _ = writeln!(out, "### {}\n\nSource: `{}` · {}\n\n--- exact instruction body ---\n{}\n--- end instruction body ---\n",
                field("/source/title"), field("/source/record_id"), field("/scope"), field("/content"));
        }
    }
    if let Some(diagnostics) = value
        .pointer("/instructions/diagnostics")
        .and_then(Value::as_array)
    {
        for diagnostic in diagnostics {
            let _ = writeln!(
                out,
                "Standing instructions are partial: binding `{}` targets record `{}`. {}",
                diagnostic["binding_id"].as_str().unwrap_or(""),
                diagnostic["record_id"].as_str().unwrap_or(""),
                diagnostic["reason"].as_str().unwrap_or("")
            );
        }
    }
    out.push_str("## KernelV2 limitations\n\n");
    if let Some(notes) = value
        .get("unsupported_capabilities")
        .and_then(Value::as_array)
    {
        for note in notes.iter().filter_map(Value::as_str) {
            let _ = writeln!(out, "- {note}");
        }
    }
    let state_note = if value.pointer("/run/closed").and_then(Value::as_bool) == Some(true) {
        "This run is closed; bootstrap retains its key for correlation."
    } else {
        "Bootstrap opens a durable run owned by the authenticated principal. Repeating bootstrap with this key continues the same open run."
    };
    let _ = writeln!(
        out,
        "\n## Run continuation\n\nRun key: `{}`\n\n{} {}",
        text("/session/run_key"),
        state_note,
        text("/session/guidance")
    );
    out
}
