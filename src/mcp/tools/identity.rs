//! General-purpose governed binding and shadow-resolution tools.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::db::Db;
use crate::error::{Error, Result};
use crate::identity::{
    self, BindingClaim, MaterializationPolicy, MutationContext, ObservationProvenance,
    ObservationQuality, StubHints,
};
use crate::mcp::registry::{Caller, ToolRegistry};
use crate::mcp::ToolKind;

use super::{parse_args, require_nonblank_reason, REASON_DESCRIPTION};

fn context<'a>(caller: &'a Caller, reason: &'a str) -> MutationContext<'a> {
    MutationContext {
        actor: caller.actor(),
        reason,
        run_key: caller.run_key(),
        parent_key: caller.parent_key(),
        intent: caller.intent(),
        internal: false,
        source_read_authorized: false,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveExternalArgs {
    bindings: Vec<BindingClaim>,
    #[serde(default)]
    hints: StubHints,
    reason: String,
}

async fn resolve_external(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: ResolveExternalArgs = parse_args("resolve_external", arguments)?;
    require_nonblank_reason("resolve_external", &args.reason)?;
    let result = identity::resolve_external(
        &db,
        &context(&caller, &args.reason),
        &args.bindings,
        &args.hints,
    )
    .await?;
    Ok(json!({
        "status": if result.created { "created" } else { "resolved" },
        "record_id": result.record_id,
        "created": result.created,
        "bindings_added": result.bindings_added,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ManageBindingsArgs {
    List {
        record_id: String,
    },
    Observations {
        record_id: String,
        #[serde(default = "default_observation_limit")]
        limit: i64,
    },
    Add {
        record_id: String,
        binding: BindingClaim,
        #[serde(default)]
        canonical: bool,
        reason: String,
        #[serde(default)]
        if_binding_state_revision: Option<String>,
    },
    Remove {
        record_id: String,
        binding: BindingClaim,
        reason: String,
        #[serde(default)]
        if_binding_state_revision: Option<String>,
    },
    Canonicalize {
        record_id: String,
        binding: BindingClaim,
        reason: String,
        #[serde(default)]
        if_binding_state_revision: Option<String>,
    },
    Reconcile {
        target_record_id: String,
        expected_source_record_id: String,
        bindings: Vec<BindingClaim>,
        #[serde(default)]
        apply: bool,
        reason: Option<String>,
        #[serde(default)]
        if_binding_state_revision: Option<String>,
    },
}

fn default_observation_limit() -> i64 {
    20
}

async fn manage_bindings(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    match parse_args("manage_bindings", arguments)? {
        ManageBindingsArgs::List { record_id } => Ok(json!({
            "status": "listed",
            "record_id": record_id,
            "bindings": identity::list_bindings(&db, caller.actor(), &record_id).await?,
        })),
        ManageBindingsArgs::Observations { record_id, limit } => Ok(json!({
            "status": "listed",
            "record_id": record_id,
            "observations": identity::list_observations(&db, caller.actor(), &record_id, limit).await?,
        })),
        ManageBindingsArgs::Add {
            record_id,
            binding,
            canonical,
            reason,
            if_binding_state_revision,
        } => {
            require_nonblank_reason("manage_bindings", &reason)?;
            let changed = identity::add_binding_if_revision(
                &db,
                &context(&caller, &reason),
                &record_id,
                &binding,
                canonical,
                if_binding_state_revision.as_deref(),
            )
            .await?;
            Ok(
                json!({"status": if changed {"added"} else {"unchanged"}, "record_id": record_id, "changed": changed}),
            )
        }
        ManageBindingsArgs::Remove {
            record_id,
            binding,
            reason,
            if_binding_state_revision,
        } => {
            require_nonblank_reason("manage_bindings", &reason)?;
            let changed = identity::remove_binding_if_revision(
                &db,
                &context(&caller, &reason),
                &record_id,
                &binding,
                if_binding_state_revision.as_deref(),
            )
            .await?;
            Ok(
                json!({"status": if changed {"removed"} else {"unchanged"}, "record_id": record_id, "changed": changed}),
            )
        }
        ManageBindingsArgs::Canonicalize {
            record_id,
            binding,
            reason,
            if_binding_state_revision,
        } => {
            require_nonblank_reason("manage_bindings", &reason)?;
            let changed = identity::canonicalize_binding_if_revision(
                &db,
                &context(&caller, &reason),
                &record_id,
                &binding,
                if_binding_state_revision.as_deref(),
            )
            .await?;
            Ok(json!({
                "status": if changed { "canonicalized" } else { "unchanged" },
                "record_id": record_id,
                "changed": changed
            }))
        }
        ManageBindingsArgs::Reconcile {
            target_record_id,
            expected_source_record_id,
            bindings,
            apply,
            reason,
            if_binding_state_revision,
        } => {
            let reason = reason.unwrap_or_default();
            if apply {
                require_nonblank_reason("manage_bindings", &reason)?;
            }
            let selected = identity::reconcile_bindings_if_revision(
                &db,
                &context(&caller, &reason),
                &target_record_id,
                &expected_source_record_id,
                &bindings,
                apply,
                if_binding_state_revision.as_deref(),
            )
            .await?;
            Ok(json!({
                "status": if apply {"reconciled"} else {"preview"},
                "record_id": target_record_id,
                "from_record_id": expected_source_record_id,
                "to_record_id": target_record_id,
                "bindings": selected,
                "changed": apply,
            }))
        }
    }
}

/// Parse one exact production mutation variant for the executor plan runtime.
/// Reconciliation plans always represent the mutating `apply=true` path; the
/// plan preparation response itself is the non-mutating preview.
#[cfg(feature = "mcp-executor-prototype")]
pub(crate) fn validate_binding_mutation(expected_action: &str, arguments: Value) -> Result<()> {
    match (expected_action, parse_args("manage_bindings", arguments)?) {
        (
            "add",
            ManageBindingsArgs::Add {
                reason,
                record_id: _,
                binding: _,
                canonical: _,
                if_binding_state_revision: _,
            },
        )
        | (
            "remove",
            ManageBindingsArgs::Remove {
                reason,
                record_id: _,
                binding: _,
                if_binding_state_revision: _,
            },
        )
        | (
            "canonicalize",
            ManageBindingsArgs::Canonicalize {
                reason,
                record_id: _,
                binding: _,
                if_binding_state_revision: _,
            },
        ) => require_nonblank_reason("manage_bindings", &reason),
        (
            "reconcile",
            ManageBindingsArgs::Reconcile {
                apply: true,
                reason: Some(reason),
                target_record_id: _,
                expected_source_record_id: _,
                bindings: _,
                if_binding_state_revision: _,
            },
        ) => require_nonblank_reason("manage_bindings", &reason),
        ("reconcile", ManageBindingsArgs::Reconcile { .. }) => Err(Error::engine(
            "manage_bindings: planned reconcile requires apply=true and a nonblank reason",
        )),
        (expected, _) => Err(Error::engine(format!(
            "manage_bindings: executor preparation expected action '{expected}'"
        ))),
    }
}

/// Resolve the exact visible identity-binding effect without mutation. This
/// owns the production tagged parser and caller context; `crate::identity`
/// owns normalization, system policy, authorization and live-state projection.
#[cfg(feature = "mcp-executor-prototype")]
pub(crate) async fn prepare_binding_mutation(
    db: &Db,
    caller: &Caller,
    expected_action: &str,
    arguments: Value,
) -> Result<identity::BindingMutationPreparation> {
    match (expected_action, parse_args("manage_bindings", arguments)?) {
        (
            "add",
            ManageBindingsArgs::Add {
                record_id,
                binding,
                canonical,
                reason,
                if_binding_state_revision: _,
            },
        ) => {
            require_nonblank_reason("manage_bindings", &reason)?;
            identity::prepare_add_binding(
                db,
                &context(caller, &reason),
                &record_id,
                &binding,
                canonical,
            )
            .await
        }
        (
            "remove",
            ManageBindingsArgs::Remove {
                record_id,
                binding,
                reason,
                if_binding_state_revision: _,
            },
        ) => {
            require_nonblank_reason("manage_bindings", &reason)?;
            identity::prepare_remove_binding(db, &context(caller, &reason), &record_id, &binding)
                .await
        }
        (
            "canonicalize",
            ManageBindingsArgs::Canonicalize {
                record_id,
                binding,
                reason,
                if_binding_state_revision: _,
            },
        ) => {
            require_nonblank_reason("manage_bindings", &reason)?;
            identity::prepare_canonicalize_binding(
                db,
                &context(caller, &reason),
                &record_id,
                &binding,
            )
            .await
        }
        (
            "reconcile",
            ManageBindingsArgs::Reconcile {
                target_record_id,
                expected_source_record_id,
                bindings,
                apply: true,
                reason: Some(reason),
                if_binding_state_revision: _,
            },
        ) => {
            require_nonblank_reason("manage_bindings", &reason)?;
            identity::prepare_reconcile_bindings(
                db,
                &context(caller, &reason),
                &target_record_id,
                &expected_source_record_id,
                &bindings,
            )
            .await
        }
        ("reconcile", ManageBindingsArgs::Reconcile { .. }) => Err(Error::engine(
            "manage_bindings: planned reconcile requires apply=true and a nonblank reason",
        )),
        (expected, _) => Err(Error::engine(format!(
            "manage_bindings: executor preparation expected action '{expected}'"
        ))),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObserveExternalArgs {
    bindings: Vec<BindingClaim>,
    source_binding: BindingClaim,
    #[serde(default)]
    hints: StubHints,
    quality: ObservationQuality,
    materialization_policy: MaterializationPolicy,
    as_of: Option<String>,
    provenance: ObservationProvenance,
    display_name: Option<String>,
    snapshot_base64: Option<String>,
    snapshot_mime: Option<String>,
    snapshot_filename: Option<String>,
    reason: String,
}

async fn observe_external(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: ObserveExternalArgs = parse_args("observe_external", arguments)?;
    require_nonblank_reason("observe_external", &args.reason)?;
    let snapshot = args
        .snapshot_base64
        .as_deref()
        .map(|encoded| {
            STANDARD
                .decode(encoded)
                .map_err(|_| Error::engine("observe_external: snapshot_base64 is malformed"))
        })
        .transpose()?;
    let result = identity::observe_external(
        &db,
        &context(&caller, &args.reason),
        &args.bindings,
        &args.hints,
        &args.source_binding,
        args.quality,
        args.materialization_policy,
        args.as_of.as_deref(),
        &args.provenance,
        args.display_name.as_deref(),
        snapshot.as_deref(),
        args.snapshot_mime.as_deref(),
        args.snapshot_filename.as_deref(),
    )
    .await?;
    Ok(json!({
        "status": "observed",
        "record_id": result.record_id,
        "observation_id": result.observation_id,
        "created": result.created,
        "materialization_policy": args.materialization_policy,
        "quality": args.quality,
        "provenance": result.provenance,
        "attachment_id": result.provenance_attachment_id,
    }))
}

pub fn register_identity_tools(registry: &mut ToolRegistry) -> Result<()> {
    let binding_schema = json!({
        "type": "object",
        "properties": {"system": {"type":"string"}, "identifier": {"type":"string"}},
        "required": ["system", "identifier"], "additionalProperties": false
    });
    let hints_schema = json!({
        "type":"object",
        "properties":{"record_type":{"type":"string"},"kind":{"type":"string"},"name":{"type":"string"}},
        "additionalProperties":false
    });
    let provenance_schema = json!({
        "type":"object",
        "properties":{
            "source_revision":{"type":"string","minLength":1,"description":"Opaque source revision represented by newly captured bytes. Required for a captured snapshot; retained snapshots inherit it from retained_from_observation_id."},
            "source_digest":{"type":"string","minLength":1,"description":"Optional source-provided digest. This is distinct from the local blob SHA-256."},
            "freshness":{"type":"string","enum":["unknown","fresh","stale"]},
            "retention_state":{"type":"string","enum":["none","captured","retained"]},
            "source_availability":{"type":"string","enum":["unknown","available","unavailable"]},
            "refresh_outcome":{"type":"string","enum":["not_attempted","succeeded","failed"]},
            "retained_from_observation_id":{"type":"string","description":"Prior same-record, same-source snapshot observation whose immutable attachment remains retained. Required only for retained."}
        },
        "required":["freshness","retention_state","source_availability","refresh_outcome"],
        "additionalProperties":false
    });
    registry.register(ToolKind::ResolveExternal,
        "Resolve governed external identities to exactly one visible local record. A miss atomically creates an identity-only shadow and audited bindings; repeated normalized claims are idempotent. Conflicting claims fail closed. Creation hints never overwrite a hit. Public callers may use native-principal and native-record; email/account are reserved verified hosting/engine systems.",
        json!({"type":"object","properties":{"bindings":{"type":"array","minItems":1,"items":binding_schema.clone()},"hints":hints_schema.clone(),"reason":{"type":"string","minLength":1,"description":REASON_DESCRIPTION}},"required":["bindings","reason"],"additionalProperties":false}),
        resolve_external)?;
    registry.register(ToolKind::ManageBindings,
        "List or govern plural external identities. Writes require record manage authority and an audited reason. Add is idempotent, collisions fail closed, canonicalize preserves at most one canonical identity per system, and reconcile preview/apply transfers selected bindings only—never record fields, bodies, facets, links, or records.",
        json!({"type":"object","properties":{"action":{"type":"string","enum":["list","observations","add","remove","canonicalize","reconcile"]},"record_id":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":50,"default":20},"binding":binding_schema.clone(),"canonical":{"type":"boolean"},"target_record_id":{"type":"string"},"expected_source_record_id":{"type":"string"},"bindings":{"type":"array","items":binding_schema.clone()},"apply":{"type":"boolean","default":false},"reason":{"type":"string","description":REASON_DESCRIPTION}},"required":["action"],"additionalProperties":false}),
        manage_bindings)?;
    registry.register(ToolKind::ObserveExternal,
        "Atomically resolve/create a shadow and append a qualified external observation. materialization_policy and provenance are mandatory. identity_only stores no readable bytes. A captured snapshot requires fresh source revision metadata and immutable attachment content. A failed refresh may retain a prior same-source attachment only as retained/stale provenance; it never relabels old bytes as newly fetched truth. This public local surface intentionally has no remote source-read proof, so fetched/snapshot calls fail with snapshot_authorization_failure until invoked through a verified gateway; reported identity_only remains available.",
        json!({"type":"object","properties":{"bindings":{"type":"array","minItems":1,"items":binding_schema.clone()},"source_binding":binding_schema,"hints":hints_schema,"quality":{"type":"string","enum":["reported","fetched"]},"materialization_policy":{"type":"string","enum":["identity_only","snapshot"]},"as_of":{"type":"string"},"provenance":provenance_schema,"display_name":{"type":"string"},"snapshot_base64":{"type":"string"},"snapshot_mime":{"type":"string"},"snapshot_filename":{"type":"string"},"reason":{"type":"string","minLength":1,"description":REASON_DESCRIPTION}},"required":["bindings","source_binding","quality","materialization_policy","provenance","reason"],"additionalProperties":false}),
        observe_external)?;
    Ok(())
}
