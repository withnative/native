//! Owner-only hosted authority act-delta operations.
//!
//! These are the hosted MCP doors to the authenticated act-delta transport.
//! They are registered only by the hosted runtime; stdio never registers them,
//! so no local process can expose a hosted trust path. Both require HostOwner
//! footing (see [`ToolKind`] classification) and the source re-checks the
//! caller's owner membership against the selected route on every call before
//! reading anything.
//!
//! `authority_act_head` is the cheap probe: it returns the authority's
//! replicated head coordinates so a client can decide whether a cut is needed.
//! `authority_act_delta` is the exact cut: the client supplies `F1` and optional v2 base blob keys, and the
//! authority returns the canonical delta from its own observed head `F2`. If
//! the exact delta exceeds the bounded transport ceiling it refuses, so the
//! caller can take the whole-snapshot fallback rather than receive a partial
//! delta.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::Result;
use crate::mcp::authority_act::{AuthorityActDeltaRequest, AuthorityActSourceRef};
use crate::mcp::registry::{Caller, ToolRegistry};
use crate::mcp::ToolKind;

use super::parse_args;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyArgs {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityActDeltaArgs {
    from_exclusive_act: i64,
    blob_inventory: Option<Vec<String>>,
}

const AUTHORITY_ACT_HEAD_DESCRIPTION: &str = "Owner-only replicated authority act-head probe for local standby delta refresh. Returns the authority's replicated head coordinates (origin, head act, per-log and non-sequenced watermarks, cutovers, binding seeds and pins) without creating a snapshot. Hosted and HostOwner-only; absent on local/stdio.";
const AUTHORITY_ACT_DELTA_DESCRIPTION: &str = "Owner-only exact canonical authority act-delta cut for local standby delta refresh. Supply from_exclusive_act (F1); v2 also requires sorted SHA-256 blob_inventory from the verified base. The authority cuts to the head it observes in the same read transaction (F2) and returns the canonical delta bytes with an outer digest. Refuses a cut above the bounded transport ceiling so the caller can fall back to a whole snapshot. Hosted and HostOwner-only; absent on local/stdio.";

fn authority_act_head_schema() -> Value {
    json!({
        "type": "object",
        "properties": {},
        "additionalProperties": false
    })
}

fn authority_act_delta_schema() -> Value {
    json!({
        "type": "object",
        "required": ["from_exclusive_act"],
        "properties": {
            "blob_inventory": {"type":"array","maxItems":65536,"items":{"type":"string","pattern":"^[0-9a-f]{64}$"},"description":"Sorted unique SHA-256 keys in the verified v2 base; required for v2 deltas after act zero."},
            "from_exclusive_act": {
                "type": "integer",
                "minimum": 0,
                "description": "Exclusive lower bound F1. The authority observes F2 itself."
            }
        },
        "additionalProperties": false
    })
}

async fn authority_act_head(
    db: crate::db::Db,
    caller: Caller,
    arguments: Value,
    source: AuthorityActSourceRef,
) -> Result<Value> {
    let _: EmptyArgs = parse_args("authority_act_head", arguments)?;
    let response = source.head(db, caller).await?;
    serde_json::to_value(response).map_err(Into::into)
}

async fn authority_act_delta(
    db: crate::db::Db,
    caller: Caller,
    arguments: Value,
    source: AuthorityActSourceRef,
) -> Result<Value> {
    let args: AuthorityActDeltaArgs = parse_args("authority_act_delta", arguments)?;
    let response = source
        .delta(
            db,
            caller,
            AuthorityActDeltaRequest {
                from_exclusive_act: args.from_exclusive_act,
                blob_inventory: args.blob_inventory,
            },
        )
        .await?;
    serde_json::to_value(response).map_err(Into::into)
}

/// Register both owner-only authority act operations against one hosted source.
pub fn register_authority_act_tools(
    registry: &mut ToolRegistry,
    source: AuthorityActSourceRef,
) -> Result<()> {
    #[cfg(feature = "v2-kernel-probe")]
    let kernel_source = source.clone();
    let head_source = source.clone();
    registry.register(
        ToolKind::AuthorityActHead,
        AUTHORITY_ACT_HEAD_DESCRIPTION,
        authority_act_head_schema(),
        move |db, caller, arguments| {
            let source = head_source.clone();
            async move { authority_act_head(db, caller, arguments, source).await }
        },
    )?;
    registry.register(
        ToolKind::AuthorityActDelta,
        AUTHORITY_ACT_DELTA_DESCRIPTION,
        authority_act_delta_schema(),
        move |db, caller, arguments| {
            let source = source.clone();
            async move { authority_act_delta(db, caller, arguments, source).await }
        },
    )?;
    #[cfg(feature = "v2-kernel-probe")]
    for name in ["authority_act_head", "authority_act_delta"] {
        let source = kernel_source.clone();
        registry.register_engine_handler(
            name,
            crate::mcp::registry::EngineKind::KernelV2,
            move |engine, caller, args| {
                let source = source.clone();
                async move {
                    let crate::mcp::registry::EngineHandle::KernelV2(db) = engine else {
                        unreachable!()
                    };
                    if name == "authority_act_head" {
                        authority_act_head(db, caller, args, source).await
                    } else {
                        authority_act_delta(db, caller, args, source).await
                    }
                }
            },
        )?;
    }
    Ok(())
}

/// Register only the maximal-hosted descriptors for deterministic generators.
///
/// Generated registries are never dispatched; hosted composition must use a
/// concrete source through [`register_authority_act_tools`].
#[doc(hidden)]
pub fn register_authority_act_tool_schema(registry: &mut ToolRegistry) -> Result<()> {
    let unavailable: AuthorityActSourceRef = std::sync::Arc::new(SchemaOnlyAuthorityActSource);
    register_authority_act_tools(registry, unavailable)?;
    registry.mark_engine_operations_unavailable(
        ToolKind::AuthorityActHead.name(),
        crate::mcp::EngineKind::Sqlite,
    )?;
    registry.mark_engine_operations_unavailable(
        ToolKind::AuthorityActDelta.name(),
        crate::mcp::EngineKind::Sqlite,
    )
}

struct SchemaOnlyAuthorityActSource;

impl crate::mcp::authority_act::AuthorityActSource for SchemaOnlyAuthorityActSource {
    fn head(
        &self,
        _db: crate::db::Db,
        _caller: Caller,
    ) -> futures::future::BoxFuture<
        'static,
        Result<crate::standby::delta_transport::AuthorityActHeadResponseV1>,
    > {
        Box::pin(async {
            Err(crate::error::Error::engine(
                "authority_act_head schema-only delegate cannot be dispatched",
            ))
        })
    }

    fn delta(
        &self,
        _db: crate::db::Db,
        _caller: Caller,
        _request: AuthorityActDeltaRequest,
    ) -> futures::future::BoxFuture<
        'static,
        Result<crate::standby::delta_transport::AuthorityActDeltaResponseV1>,
    > {
        Box::pin(async {
            Err(crate::error::Error::engine(
                "authority_act_delta schema-only delegate cannot be dispatched",
            ))
        })
    }
}
